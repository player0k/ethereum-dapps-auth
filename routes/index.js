var express = require('express');
var router = express.Router();
var ethUtil = require('ethereumjs-util');
var jwt = require('jsonwebtoken');
var randomstring = require('randomstring');

/* GET home page. */
router.get('/', function (req, res, next) {
    res.render('index', {title: 'MetaMask login'});
});

router.get('/web3', function (req, res, next) {
    res.render('web3modal', {title: 'Web3 modal login'})
})

//should store as field in user wallets table
const NONCE = randomstring.generate(10)
const JWT_SALT = 'random_string'
const SIGNATURE_MSG = "Sign this message to validate that you are the owner of the account. Random string: "


router.post('/login', function (req, res, next) {
    console.log(req.body.owner)
    return res.send({
        success: true,
        result: {
            message: SIGNATURE_MSG + NONCE
        }
    })
})

router.post('/auth', async function (req, res, next) {
    try {
        let data = SIGNATURE_MSG + NONCE

        function toHex(s) {
            var hex = '';
            for (var i = 0; i < s.length; i++) {
                hex += '' + s.charCodeAt(i).toString(16);
            }
            return `0x${hex}`;
        }

        var sig = req.body.sig;
        var owner = req.body.owner;

        var message = ethUtil.toBuffer(toHex(data))
        var msgHash = ethUtil.hashPersonalMessage(message)

        // Get the address of whoever signed this message
        var signature = ethUtil.toBuffer(sig)
        var sigParams = ethUtil.fromRpcSig(signature)
        var publicKey = ethUtil.ecrecover(msgHash, sigParams.v, sigParams.r, sigParams.s)
        var sender = ethUtil.publicToAddress(publicKey)
        var addr = ethUtil.bufferToHex(sender)

        // Determine if it is the same address as 'owner'
        var match = false;
        if (addr == owner) {
            match = true;
        }

        if (match) {
            // If the signature matches the owner supplied, create a
            // JSON web token for the owner that expires in 24 hours.
            ///var token = jwt.sign({user: req.body.addr}, 'i am another string',  { expiresIn: '1d' });

            var accessToken = jwt.sign({
                accessToken: true,
                address: addr,
                exp: parseInt(Date.now() / 1000) + 60 * 15
            }, JWT_SALT, {algorithm: 'HS512', subject: addr});
            var refreshToken = jwt.sign({
                address: addr,
                exp: parseInt(Date.now() / 1000) + 60 * 60 * 24 * 7
            }, JWT_SALT, {algorithm: 'HS512', subject: addr});

            return res.send({success: true, result: {accessToken, refreshToken}})
        } else {
            // If the signature doesn’t match, error out
            return res.status(400).send({success: false, err: 'Signature did not match.'});
        }
    } catch (e) {
        console.error(e);
    }

    return res.status(500).send({success: false, message: 'Internal server error'})
})

router.post('/logout', function (req, res) {
    let token = String(req.headers['authorization'] || '').replace(/^(Bearer\s+)/, '')
    jwt.verify(token, JWT_SALT, (err, decoded) => {
        if (err) {
            return res.status(500).send({success: false, result: {message: err.message}})
        }
        return res.send({success: true, result: {message: "Signed out successfully"}})
    })
})

module.exports = router;
