var dgram = require('dgram');
var net = require('net');

var FLAG_DATA = 0x10;
var FLAG_CONNECT = 0x11;
var FLAG_DISCONNECT = 0x12;
var FLAG_NOP = 0xff;

var TYPE_TXT = 0x0c;


function _init(fakeDNS) {

  var iargs = {}, args = {};
  
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


  args.mode = iargs.m || iargs.mode || 'server';
  args.appmode = iargs.a || iargs.appmode || 'listen';
  args.domain = iargs.d || iargs.domain || 'x.co';
  args.dnsport = parseInt( iargs.dnsport );
  args.dnsip = iargs.dnsip;
  args.clientport = parseInt( iargs.c || iargs.clientport ) || 5354;
  args.appport = parseInt( iargs.appport );
  args.appip = iargs.appip;
  args.sliceSize = parseInt(iargs.s || iargs['slice-size']) || 128;

  if( iargs.h || iargs.help || !iargs.appip || !iargs.appport || !iargs.dnsip || !iargs.dnsport ) {
    return showUsage();
  }
  
  var fd = new fakeDNS(args);
  fd.start()
}

function showUsage() {
  console.log(""+
    "Usage : \n"+
    "dnstunnel [-d domain] [-m server|client] [ -c clientport ] [-s slicesize] dnsip:dnsport:appip:appport\n"
  );
}

fakeDNS = function(args) {

  this.args = args;
  this.SENDBUFFER = []; 
  this.RECVBUFFER = []; 
  this.s = dgram.createSocket("udp4");
  this.appClient = null;
  this.appServer = null;
  this.id = 0;
}

fakeDNS.prototype.parsePacket = function(buffer) {
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
}

fakeDNS.prototype.buildPacket = function( packet ) {
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

fakeDNS.prototype.listenApp = function() {

  var self = this;
  self.appServer = net.createServer( function(c) {
    console.log("client connected");
    self.addChunk(new Buffer('CON'));

    c.on('close', function() {
      console.log("client connection ended");
      self.addChunk(new Buffer('END'));
    });

    c.on('data', function(data) {
      self.addChunk(data);
    });

    self.appClient = c;
  });

  this.appServer.listen(this.args.appport, this.args.appip, function() {
    console.log("server bound");
  });
}

fakeDNS.prototype.connectApp = function() {
  console.log("Connect Cmd Received2");
  this.appClient = new net.Socket();

  console.log("Connecting to " + this.appip + ":" + this.appport);
  this.appClient.connect(this.args.appport, this.args.appip,
    function() { //'connect' listener
      console.log('connected to server!');
    }
  );

  this.appClient.on('data', function(data) {
    console.log(data.toString());
  });

  this.appClient.on('end', function() {
    console.log('disconnected from server');
  });
}

fakeDNS.prototype.disconnectApp = function() {
  console.log("Disconnect Cmd Received2");
  this.appClient.close();
}

fakeDNS.prototype.start = function() {
  
  if(this.args.mode == 'server') {
    this.startServer();
    //this.listenApp();
  }else
  {
    this.startClient();
  }

};

fakeDNS.prototype.startServer = function() {
  var self = this;
  self.s.on('error', function(err) {
    console.error(err);
    self.s.close();
  });
  self.s.on('message', function(data, remote) {
    var q = self.parsePacket(data);
    console.log(remote,q);
    
    var packet = self.getNextPacketOrNOP();
    var buffer = self.buildPacket(packet);
    self.s.send(buffer, 0, buffer.length, remote.port, remote.address, function(err) {
    });

  });
  self.s.on('listening', function() {
    var address = self.s.address();
    console.log("Listening " + address.address + ":" + address.port)
  });
  self.s.bind(self.args.dnsport, self.args.dnsip);
};

fakeDNS.prototype.startClient = function() {

  var self = this;

  self.s.bind( self.args.clientport, '0.0.0.0');

  self.s.on('message', function(data) {
    var packet = self.parsePacket(data);
    console.log(packet);
  });

  var consumer;
  consumer = function() {
    var packet = self.getNextPacketOrNOP();
    var buffer = self.buildPacket(packet);
    self.s.send(buffer, 0, buffer.length, self.args.dnsport, self.args.dnsip, function(err) {
      setTimeout( consumer, packet.flag == FLAG_NOP ? 1000 : 30);
    });
  };
  consumer();
};

fakeDNS.prototype.getNextPacketOrNOP = function() {

  var data = this.SENDBUFFER.shift();

  if(data && data.length) {
    return {
      id:++this.id % 0xffff,
      flag:FLAG_DATA,
      data:data,
      query:true,
      domain:this.args.domain
    };
  }else{
    return {
      id:++this.id % 0xffff,
      flag:FLAG_NOP,
      data:new Buffer("NOP"),
      query:true,
      domain:this.args.domain
    };
  }
};

fakeDNS.prototype.addChunk = function(chunk) {
  var self = this;
  if(!chunk || !chunk.length) return;
  var start = 0;
  do{
    var end = start + Math.min(self.args.sliceSize, chunk.length - start);
    var c = chunk.slice(start, end);
    start += c.length;
    this.SENDBUFFER.push(c);
  }while(start<chunk.length);
};

_init(fakeDNS);

