var dgram = require('dgram');
var net = require('net');

var FLAG_DATA = 0x10;
var FLAG_CONNECT = 0x11;
var FLAG_DISCONNECT = 0x12;
var FLAG_NOP = 0xff;

var TYPE_TXT = 0x0c;

function OnDNS() {
  this.QUEUE = []; 
  this.s = dgram.createSocket("udp4");
  this.appClient = null;
  this.appServer = null;
  this.id = 0;
  this.NOPStart = -1;
}

OnDNS.prototype.init = function() {
  var iargs = {};
  
  if(process.argv.length <= 2) {
    iargs['help'] = true;
  }

  for(var i=2; i<process.argv.length; i++) {
    var par = process.argv[i];
    if(par[0] == '-') {
      var dashes = 1;
      if(par[1] == '-') dashes = 2;

      if(
        par.substring(dashes) == 'help' || 
        par.substring(dashes) == 'h' 
      ) { 
        iargs[par.substring(dashes)] = true;
        continue;
      }

      iargs[par.substring(dashes)] = process.argv[++i];
    }else{
      var ipport =  par.split(':');
      if(ipport.length != 4) {
        iargs.help = true;
        break;
      }else{
        iargs.dnsip = ipport[0];
        iargs.dnsport = ipport[1];
        iargs.appip = ipport[2];
        iargs.appport = ipport[3];
      }
    }
  }


  this.mode = iargs.m || iargs.mode || 'server';
  this.appmode = iargs.a || iargs.appmode || 'listen';
  this.domain = iargs.d || iargs.domain || 'x.co';
  this.dnsport = parseInt( iargs.dnsport );
  this.dnsip = iargs.dnsip;
  this.clientport = parseInt( iargs.c || iargs.clientport ) || 5354;
  this.appport = parseInt( iargs.appport );
  this.appip = iargs.appip;
  this.sliceSize = parseInt(iargs.s || iargs['slice-size']) || 128;

  if( iargs.h || iargs.help || !iargs.appip || !iargs.appport || !iargs.dnsip || !iargs.dnsport ) {
    return -1;
  }
};

OnDNS.prototype.LOG = function() {
  return;
  console.log.apply(this, arguments);
};

OnDNS.prototype.start = function() {
  
  if(this.mode == 'server') {
    this.startServer();
    this.listenApp();
  }else{
    this.startClient();
  }

};

OnDNS.prototype.showUsage = function() {
  this.LOG(""+
    "Usage : \n"+
    "dnstunnel [-d domain] [-m server|client] [ -c clientport ] [-s slicesize] dnsip:dnsport:appip:appport\n"
  );
};

OnDNS.prototype.buildPacket = function( packet ) {
  //id, flag, data, query) {
  var nId = 2, nFlag = 2;
  var dataLength = nId + nFlag + packet.data.length;
  var dataBuffer = new Buffer( dataLength );
  var pos = 0;
  dataBuffer.writeUInt16BE(packet.id, pos); pos += 2;
  dataBuffer.writeUInt16BE(packet.flag, pos); pos += 2;
  packet.data.copy(dataBuffer, pos, 0);

  var dom_parts = packet.domain.split('.');
  var dom = dom_parts[0];
  var tld = dom_parts[1];

  var b64data = dataBuffer.toString('base64');

  var buffer;
  
  if(packet.query) {
    buffer = new Buffer(4 + 2 + 2 + 2 + 2 + 1 + b64data.length + 1 + dom.length + 1 + tld.length + 1 + 2 + 2);
  }else{
    buffer = new Buffer(4 + 2 + 2 + 2 + 2 + 1 + 2 + 2 + 2 + 4 + 2 + b64data.length);
  }

  pos = 0;

  // DNS Query / Response Id
  buffer.writeUInt16BE(packet.id,pos); pos += 2;

  var Flags = packet.query ? 0x0100 :  0x8180;
  buffer.writeUInt16BE(Flags, pos); pos += 2;
  
  var QDCOUNT = 0x0001;
  buffer.writeUInt16BE(QDCOUNT, pos); pos += 2;

  var ANCOUNT = packet.query ? 0x0000 : 0x0001;
  buffer.writeUInt16BE(ANCOUNT, pos); pos += 2;

  var NSCOUNT = 0x0000;
  buffer.writeUInt16BE(NSCOUNT, pos); pos += 2;

  var ARCOUNT = 0x0000;
  buffer.writeUInt16BE(ARCOUNT, pos); pos += 2;

  if(packet.query) {

    // data
    buffer.writeUInt8(b64data.length,pos); pos++;
    buffer.write(b64data,pos,b64data.length);  pos += b64data.length;

    // dom
    buffer.writeUInt8(dom.length,pos); pos++;
    buffer.write(dom,pos,dom.length); pos += dom.length;

    // tld
    buffer.writeUInt8(tld.length,pos); pos++;
    buffer.write(tld,pos,tld.length); pos += tld.length;

    // zero pad
    buffer.writeUInt8(0,pos);  pos++;

    // Query Type TXT (16)
    buffer.writeUInt16BE(16,pos); pos += 2;

    // Query Class IN (1)
    buffer.writeUInt16BE(1,pos); pos++;
  }else{

    // TXT record
    buffer.writeUInt8(TYPE_TXT,pos); pos++;

    // data offset
    buffer.writeUInt16BE(0x000c,pos); pos += 2;

    // TYPE A
    buffer.writeUInt16BE(0x0001,pos); pos += 2;

    // CLASS IN
    buffer.writeUInt16BE(0x0001,pos); pos += 2;
    
    // TTL 0
    buffer.writeUInt32BE(0x00000000,pos); pos += 4;

    // length
    buffer.writeUInt16BE(b64data.length,pos); pos += 2;

    // data
    buffer.write(b64data,pos,b64data.length);  pos += b64data.length;
  }

  return buffer;

}

OnDNS.prototype.parsePacket = function(buffer) {
  var packet = {};
  packet.id = buffer.readUInt16BE(0);
  var Flags = buffer.readUInt16BE(2);
  packet.query = (Flags >> 15) == 0;

  var pos = 0x0c;
  if(packet.query) {
    var l = buffer.readUInt8(pos); pos++;
    var dataBuffer = new Buffer(buffer.slice(pos,pos+l).toString("ascii"),"base64"); pos += l;
    packet.id = dataBuffer.readUInt16BE(0);
    packet.flag = dataBuffer.readUInt16BE(2);
    packet.data = dataBuffer.slice(4);
  
    l = buffer.readUInt8(pos); pos++;
    var dom = buffer.slice(pos,pos+l).toString("ascii"); pos += l;
    
    l = buffer.readUInt8(pos); pos++;
    var tld = buffer.slice(pos,pos+l).toString("ascii"); pos += l;

    packet.domain = dom + '.' + tld;
  }else{
    pos += 10;
    // 0x0c
    pos++;
    var l = buffer.readUInt16BE(pos); pos += 2;
    var dataBuffer = new Buffer(buffer.slice(pos,pos+l).toString("ascii"),"base64"); pos += l;
    
    packet.id = dataBuffer.readUInt16BE(0);
    packet.flag = dataBuffer.readUInt16BE(2);
    packet.data = dataBuffer.slice(4);
  }

  return packet;
};

OnDNS.prototype.setAppSock = function(appsock) {

  var self = this;
  
  appsock.on('data', function(data) {
    self.LOG("Got "+data.length+" bytes from the app");
    self.queue({data:data});
  });

  appsock.on('close', function() {
    self.LOG("client connection ended");
    self.appsock = null;
    self.queue({code:FLAG_DISCONNECT});
  });

  self.appsock = appsock;

};

OnDNS.prototype.listenApp = function() {

  var self = this;
  self.appServer = net.createServer( function(appsock) {
    self.LOG("client connected");
    self.queue({code:FLAG_CONNECT});
    self.setAppSock(appsock);
  });

  this.appServer.listen(this.appport, this.appip, function() {
    self.LOG("server bound");
  });
}

OnDNS.prototype.connectApp = function() {
  
  var self = this;

  var appsock = new net.Socket();

  appsock.connect(this.appport, this.appip, function() {
    self.LOG('connected to server!');
    self.setAppSock(appsock);
  });

}

OnDNS.prototype.disconnectApp = function() {

  if(this.appsocket) {
    this.appsocket.close();
  }

}

OnDNS.prototype.startServer = function() {
  var self = this;
  self.s.on('error', function(err) {
    console.error(err);
    self.s.close();
  });
  self.s.on('message', function(data, remote) {
    self.processPacket(self.parsePacket(data));
    
    var packet = self.getNextPacketOrNOP();
    var buffer = self.buildPacket(packet);
    self.s.send(buffer, 0, buffer.length, remote.port, remote.address, function(err) {
    });

  });
  self.s.on('listening', function() {
    var address = self.s.address();
    self.LOG("Listening " + address.address + ":" + address.port)
  });
  self.s.bind(self.dnsport, self.dnsip);
};

OnDNS.prototype.processPacket = function(packet) {

  var self = this;

  switch(packet.flag) {

    case FLAG_CONNECT:
      self.LOG("Connect cmd received");
      self.connectApp();
      break;

    case FLAG_DISCONNECT:
      self.LOG("Disconnect cmd received");
      self.disconnectApp();
      break;

    case FLAG_DATA:
      if(self.appsock) {
        self.appsock.write(packet.data);
      }
      break;

    default:
      break;
  }
};

OnDNS.prototype.checkNOPThrottle = function() {
  var now = (new Date()).getTime();
  if(this.NOPStart != -1) {
    if(now - this.NOPStart > 2000) {
      return true;
    }
    return false;
  }else{
    this.NOPStart = now;
    return false;
  }
};

OnDNS.prototype.resetNOPThrottle = function() {
  this.NOPStart = -1;
};

OnDNS.prototype.startClient = function() {

  var self = this;

  self.s.bind( self.clientport, '0.0.0.0');

  self.s.on('message', function(data) {
    self.processPacket(self.parsePacket(data));
  });

  var consumer;
  consumer = function() {
    var packet = self.getNextPacketOrNOP();
    var buffer = self.buildPacket(packet);

    if(packet.flag == FLAG_NOP) {
      to = self.checkNOPThrottle() ? 1000 : 0;
      if(!self.appsock)
        to = 5000;
    }else{
      self.resetNOPThrottle();
      to = 0;
    }

    self.s.send(buffer, 0, buffer.length, self.dnsport, self.dnsip, function(err) {
      setTimeout( consumer, to);
    });
  };
  consumer();
};

OnDNS.prototype.getNextPacketOrNOP = function() {

  var item = this.QUEUE.shift();

  if(item && item.chunk) {
    this.LOG("Consuming data packet");
    return {
      id:++this.id % 0xffff,
      flag:FLAG_DATA,
      data:item.chunk,
      query:this.mode == "client",
      domain:this.domain
    };
  }else
  if(item && item.code){
    this.LOG("Consuming code packet");
    return {
      id:++this.id % 0xffff,
      flag:item.code,
      data:new Buffer("#"),
      query:this.mode == "client",
      domain:this.domain
    };
  }else{
    this.LOG("Consuming NOP packet");
    return {
      id:++this.id % 0xffff,
      flag:FLAG_NOP,
      data:new Buffer("#"),
      query:this.mode == "client",
      domain:this.domain
    };
  }
};

OnDNS.prototype.queue = function(item) {


  if(item.code) {
    this.LOG("Queuing code packet");
    return this.QUEUE.push({code:item.code});
  }else{
    if(!item.data || !item.data.length) return;
    this.LOG("Queuing data packet");

    var start = 0;
    do{
      var end = start + Math.min(this.sliceSize, item.data.length - start);
      var chunk = item.data.slice(start, end);
      start += chunk.length;
      this.QUEUE.push({chunk:chunk});
    }while(start<item.data.length);
  }
};

var ondns = new OnDNS();
if(ondns.init() == -1) {
  ondns.showUsage();
  process.exit(0);
}else{
  ondns.start();
}

