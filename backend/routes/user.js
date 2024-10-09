const express = require('express'),
 bcrypt = require("bcryptjs"),
 uuid = require("uuid"),
 jwt = require("jsonwebtoken"),
 crypto = require("crypto")

const router = express.Router();

const EXISTING_TOKENS = {}
const USER_DATABASE = [
];
const REFRESH_SIGNATURES_STORE = [];

const EXPIRIES = {
  access: '15m',
  refresh: '7d',
  administrator: '1h',
}
const SIGNATURES = {
  access: uuid.v7(),
  user: uuid.v7(),
  administrator: uuid.v7(),
  refresh: uuid.v7(),
};
const KEYS = {
  administrator: uuid.v7()
};

const generateRandomPassword = (length=8) => Array.from({ length }, () => String.fromCharCode(Math.floor(Math.random() * 62) + (Math.random() < 0.5 ? 65 : 97))).join('');
const generateUniqueReferenceId = (password) => `${crypto.pbkdf2Sync(password,crypto.randomBytes(7).toString('hex'),1000,12,'sha512',(err) => err != null && console.error(err)).toString('hex')}`;

router.get('/get-for/:mode', function(req, res) {
  const { mode } = req.params;
  switch (mode) {
    case 'DEBUG-get-admin-privilege':
      const signature = jwt.sign(SIGNATURES.administrator, KEYS.administrator, { expiresIn: EXPIRIES.administrator });
      res.status(200).json({ signature: signature })
      break;
    case 'get-access-level':
      try {
        const { userSignature } = req.body;
        const decoded = jwt.verify(userSignature, SIGNATURES.user);
        res.status(200).json({ status: `Your current site privilege is at "${decoded}" grade`, role: decoded.role });
      } catch (err) {
        return res.status(202).json({ status: `No role found, defaulting to visitor role`, role: 'visitor' });
      };
      break;
    default:
      res.status(400).json({ error: "Invalid mode" })
  };
});

router.post('/register', async function(req, res) {
  if (req.header('x-site-origin') != "admin-management")
    return res.status(403).json({ error: `Invalid origin` });
  const { username, _email } = req.body;
  const password = generateRandomPassword();
  let token;// 1 in roughly ~quadrillion (15 zeros) chances to obtain the same token id
  const generateTrueUniqueTokenId = () => {
    token = generateUniqueReferenceId(password); 
    if (EXISTING_TOKENS[token] != null)
      generateTrueUniqueTokenId();
  }
  generateTrueUniqueTokenId();

  let role = 'visitor';
  const access_level = req.header('x-user-access-level');
  if (access_level) {
    try {
      const decoded = jwt.verify(access_level, KEYS.administrator);
      switch (decoded) {
        case SIGNATURES.administrator:
          role = 'administrator';
          break;
      }
    } catch (err) {
      return res.status(403).json({ error: 'Invalid access level' });
    };
  };
  const user_info = {
    username: username,
    password: bcrypt.hashSync(password, 10),
    token: token,
    role: role,
  };
  EXISTING_TOKENS[token] = user_info;
  USER_DATABASE.push(user_info);
  // TODO, send an email to the customer
  // for now it wont be added since, shenanigans with buying a 10$ monthly plan just to anonymously (under a corporation) send an email to this user
  res.status(201).json({ status: 'Successfully registered user', raw_password: password, user_token: token});
});

const generateAndSendSignatureNext = (res, ref, filter=false, status='Successful process') => {
  const accessSignature = jwt.sign({ token: ref.token }, SIGNATURES.access, { expiresIn: EXPIRIES.access });
  const refreshSignature = jwt.sign({ token: ref.token }, SIGNATURES.refresh, { expiresIn: EXPIRIES.refresh });
  if (filter) REFRESH_SIGNATURES_STORE = REFRESH_SIGNATURES_STORE.filter(signature => signature !== refreshSignature);
  else REFRESH_SIGNATURES_STORE.push(refreshSignature);
  const userSignature = jwt.sign({ token: ref.token, role: ref.role }, SIGNATURES.user);
  res.cookie('refresh-signature', refreshSignature, { httpOnly: true, secure: true }).json({ status: status, access_signature: accessSignature, user_signature: userSignature });
}

router.post('/login', async function(req, res) {
  const { token, password } = req.body;
  if ((!token || !password) || ((token && token.length <= 0) || (password && password.length <= 0)))
    return res.status(400).json({ error: 'Missing or no credentials (User token or password)' });
  if (USER_DATABASE.length <= 0)
    return res.status(404).json({ error: 'In-Memory database is empty' });
  const ref = EXISTING_TOKENS[token];
  if (!ref)
    return res.status(401).json({ error: `Unable to find user information from database; invalid or missing token (${token})` });
  const isPasswordValid = await bcrypt.compare(password, ref.password);
  if (!isPasswordValid)
    return res.status(401).json({ error: "Invalid password" });
  generateAndSendSignatureNext(res, ref, false, 'Successfully logged-in user');
});

router.post('/updateToken', function(req, res) {
  const refreshSignature = req.cookies['refresh-signature']
  if (!refreshSignature || !REFRESH_SIGNATURES_STORE.includes(refreshSignature))
    
    return res.status(403).json({ error: "Missing signature for token refreshing"});
  jwt.verify(refreshSignature, SIGNATURES.refresh, (err, ref) => {
    if (err)
      return res.status(403).json({ error: "Failed to verify signature; signature might be expired or invalid" });
    generateAndSendSignatureNext(res, ref, true, 'Successfully refreshed sessioned log-in access for user');
  })
});

module.exports = router;
