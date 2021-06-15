const bcrypt = require('bcryptjs');

const router = require('express').Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require('../secrets'); // use this secret!

const tokenBuilder = require('./token-builder');
const Users = require('../users/users-model.js');

router.post('/register', validateRoleName, (req, res, next) => {
	/** [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response: status 201 { "user"_id: 3,
      "username": "anna",
      "role_name": "angel" } */
	let user = req.body;

	// bcrypting the password before saving
	const rounds = process.env.BCRYPT_ROUNDS || 8; // 2 ^ 8
	const hash = bcrypt.hashSync(user.password, rounds);

	// never save the plain text password in the db
	user.password = hash;

	Users.add(user)
		.then(saved => {
			res.status(201).json({
				message: `Great to have you, ${saved.username}`
			});
		})
		.catch(next); // our custom err handling middleware in server.js will trap this
});

router.post('/login', checkUsernameExists, (req, res, next) => {
	/** [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response: status 200
    { "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC" }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    } */
	// let { username, password } = req.body;
	let { password } = req.body;

	if (bcrypt.compareSync(password, req.user.password)) {
		const token = tokenBuilder(req.user);
		console.log(token);
		res.status(200).json({
			message: `Welcome back ${req.user.username}, here is token!`,
			token
		});
	} else {
		res.status(401).json({ message: 'Invalid Credentials' });
	}
});

module.exports = router;
