#!/usr/bin/env node
/* Fee Hisab license tool (seller side, keep private).
   node license-tool.js init                    -> creates license-keys.json, prints PUBLIC key to paste in index.html (LIC_PUB)
   node license-tool.js sign y 365 "School Name"  -> yearly key valid 365 days
   node license-tool.js sign l 0 "School Name"    -> lifetime key
   node license-tool.js sign y -1 "Expired demo"  -> already-expired key (for testing) */
const c=require('crypto'),fs=require('fs'),F=__dirname+'/license-keys.json',b=x=>Buffer.from(x).toString('base64url');
const [,,cmd,pl,days,...nm]=process.argv;
if(cmd==='init'){if(fs.existsSync(F)){console.log('license-keys.json already exists. Delete it first to make new keys (old licenses will stop working).');process.exit(1)}
 const k=c.generateKeyPairSync('ec',{namedCurve:'P-256'});fs.writeFileSync(F,JSON.stringify({private:k.privateKey.export({format:'jwk'}),public:k.publicKey.export({format:'jwk'})},null,1));
 console.log('Paste this as LIC_PUB in index.html:\n'+JSON.stringify(k.publicKey.export({format:'jwk'})))}
else if(cmd==='sign'){if(!fs.existsSync(F)){console.log('Run: node license-tool.js init');process.exit(1)}
 if(!['y','l'].includes(pl)){console.log('plan must be y (yearly) or l (lifetime)');process.exit(1)}
 const K=JSON.parse(fs.readFileSync(F)),now=Date.now(),id='FH-'+c.randomBytes(3).toString('hex').toUpperCase();
 const p={pr:'fee-hisab',pl,ex:pl==='l'?0:now+Math.round(+days*864e5),id,nm:nm.join(' ').slice(0,60),iat:now},ps=b(JSON.stringify(p));
 const sig=c.sign('sha256',Buffer.from(ps),{key:c.createPrivateKey({key:K.private,format:'jwk'}),dsaEncoding:'ieee-p1363'});
 console.log('FH1.'+ps+'.'+b(sig))}
else console.log('Usage: init | sign <y|l> <days> <customer name>');
