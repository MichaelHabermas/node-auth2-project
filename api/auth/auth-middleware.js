const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../secrets'); // use this secret!
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
	const token = req.headers.authorization;
	if (token) {
		jwt.verify(token, JWT_SECRET, (err, decoded) => {
			if (err) {
				next({ status: 401, message: 'Token invalid' });
			} else {
				// console.log('decoded token: ', decoded);
				req.decodedJwt = decoded;
				next();
			}
		});
	} else {
		next({ status: 401, message: 'Token required' });
	}
	/* If the user does not provide a token in the Authorization header:
  status 401 { "message": "Token required" }
  If the provided token does not verify: status 401 { "message": "Token invalid" }
  Put the decoded token in the req object, to make life easier for middlewares downstream! */
};

const only = role_name => (req, res, next) => {
	/* If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403 { "message": "This is not for you" }

    Pull the decoded token from the req object, to avoid verifying it again! */
	// console.log(`desired role_name: ${role_name}`);
	// console.log(`actual role_name: ${req.decodedJwt.role}`);

	if (role_name === req.decodedJwt.role) {
		next();
	} else {
		next({
			status: 403,
			message: 'This is not for you'
		});
	}
};

const checkUsernameExists = async (req, res, next) => {
	const { username } = req.body;
	const [user] = await Users.findBy({ username });
	if (user) {
		req.user = user;
		next();
	} else {
		next({ status: 401, message: 'Invalid credentials' });
	}
	/* If the username in req.body does NOT exist in the database
    status 401 { "message": "Invalid credentials" } */
};

const validateRoleName = async (req, res, next) => {
	let { role_name } = req.body;
	// const [role] = await Users.findBy({ role_name });
	if (!role_name || role_name.trim() === '') {
		req.role_name = 'student';
		next();
	} else if (role_name.trim() === 'admin') {
		next({ status: 422, message: 'Role name can not be admin' });
	} else {
		role_name = role_name.trim();
		if (role_name.length > 32) {
			next({
				status: 422,
				message: 'Role name can not be longer than 32 chars'
			});
		} else {
			req.role_name = role_name;
			next();
		}
	}

	// if (role_name.length > 32) {
	// 	next({
	// 		status: 422,
	// 		message: 'Role name can not be longer than 32 chars'
	// 	});
	// } else if (role_name === 'admin') {
	// 	next({ status: 422, message: 'Role name can not be admin' });
	// } else if (!role_name || role_name === '') {
	// 	req.role_name = 'student';
	// 	next();
	// } else {
	// 	req.role_name = role_name;
	// 	next();
	// }

	/* If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422 { "message": "Role name can not be admin" }

    If role_name is over 32 characters after trimming the string:
    status 422 { "message": "Role name can not be longer than 32 chars" } */
};

module.exports = {
	restricted,
	checkUsernameExists,
	validateRoleName,
	only
};
