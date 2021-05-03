const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
// import elliptic library
const EC = require('elliptic').ec;
// Create and initialize EC context
const ec = new EC('secp256k1');
// import SHA256 library from crypto-js
const SHA256 = require('crypto-js/sha256');

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

// generate keys
const key1 = ec.genKeyPair();
const key2 = ec.genKeyPair();
const key3 = ec.genKeyPair();

// encode the entire public key as a hexadecimal string
const pubKey1 = key1.getPublic().encode('hex');
const pubKey2 = key2.getPublic().encode('hex');
const pubKey3= key3.getPublic().encode('hex');

// encode the entire private keys as a hexadecimal string and their coordinates
const priKey1 = key1.getPrivate().toString(16);
// const publicX1 = key1.getPublic().x.toString(16);
// const publicY1 = key1.getPublic().y.toString(16);

const priKey2 = key2.getPrivate().toString(16);
// const publicX2 = key2.getPublic().x.toString(16);
// const publicY2 = key2.getPublic().y.toString(16);

const priKey3= key3.getPrivate().toString(16);
// const publicX3 = key3.getPublic().x.toString(16);
// const publicY3 = key3.getPublic().y.toString(16);

const balances = {
  [pubKey1]: 100,
  [pubKey2]: 50,
  [pubKey3]: 75
}
// log public keys and balances on server
console.log(balances);

const priKeyPairs = {
  priKey1: priKey1,
  priKey2: priKey2,
  priKey3: priKey3
}

// log public / private key pairs because this is just a test project :')'
console.log(priKeyPairs);


app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, privateKey, recipient, amount} = req.body;
  console.log('req.body: ', req.body);

  // sign transaction
  const priKey = ec.keyFromPrivate(privateKey, 'hex');
  const signedHash = priKey.sign(SHA256(JSON.stringify({recipient, amount})).toString());

  // verify transaction
  const pubKey = ec.keyFromPublic(sender, 'hex');
  const hash = SHA256(JSON.stringify({recipient, amount})).toString();

  if(pubKey.verify(hash, signedHash)) {
    balances[sender] -= amount;
    balances[recipient] = (balances[recipient] || 0) + +amount;
    res.send({ balance: balances[sender] });
  } else {
    res.sendStatus(400);
  }

});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});