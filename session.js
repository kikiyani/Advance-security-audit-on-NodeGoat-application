const UserDAO = require("../data/user-dao").UserDAO;
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");
const config = require("../../config/config");  

const validator= require('validator')
const jwt= require("jsonwebtoken")
const bcrypt = require("bcrypt");
const SALT_ROUNDS = 10;

/* The SessionHandler must be constructed with a connected db */
function SessionHandler(db) {
    "use strict";

    const userDAO = new UserDAO(db);
    const allocationsDAO = new AllocationsDAO(db);

    const prepareUserData = (user, next) => {
        // Generate random allocations
        const stocks = Math.floor((Math.random() * 40) + 1);
        const funds = Math.floor((Math.random() * 40) + 1);
        const bonds = 100 - (stocks + funds);

        allocationsDAO.update(user._id, stocks, funds, bonds, (err) => {
            if (err) return next(err);
        });
    };

    this.isAdminUserMiddleware = (req, res, next) => {
        if (req.session.userId) {
            return userDAO.getUserById(req.session.userId, (err, user) => {
               return user && user.isAdmin ? next() : res.redirect("/login");
            });
        }
        console.log("redirecting to login");
        return res.redirect("/login");

    };

    this.isLoggedInMiddleware = (req, res, next) => {
        if (req.session.userId) {
            return next();
        }
        console.log("redirecting to login");
        return res.redirect("/login");
    };
    this.displayLoginPage = (req, res, next) => {
        return res.render("login", {
            userName: "",
            password: "",
            loginError: "",
            environmentalScripts
        });
    };

    this.handleLoginRequest = (req, res, next) => {
    const { userName, password } = req.body;

    userDAO.validateLogin(userName, password, (err, user) => {
        const errorMessage = "Invalid username and/or password";
        const invalidUserNameErrorMessage = "Invalid username";
        const invalidPasswordErrorMessage = "Invalid password";

        if (err) {
            if (err.noSuchUser) {
                console.log("Error: attempt to login with invalid user: ", userName);
                return res.render("login", {
                    userName: userName,
                    password: "",
                    loginError: invalidUserNameErrorMessage,
                    environmentalScripts
                });
            } else if (err.invalidPassword) {
                return res.render("login", {
                    userName: userName,
                    password: "",
                    loginError: invalidPasswordErrorMessage,
                    environmentalScripts
                });
            } else {
                return next(err);
            }
        }
req.session.userId = user._id;
            return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");


    });

    };

this.handleJwtLogin = function (req, res, next) {
    const { userName, password } = req.body;

    return userDAO.validateLogin(userName, password, function (err, user) {
        if (err || !user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user._id }, config.jwtSecret, { expiresIn: "1h" });

        return res.json({ token });
    });
};



    this.displayLogoutPage = (req, res) => {
        req.session.destroy(() => res.redirect("/"));
    };

    this.displaySignupPage = (req, res) => {
        res.render("signup", {
            userName: "",
            password: "",
            passwordError: "",
            email: "",
            userNameError: "",
            verifyError: "",
            environmentalScripts
        });
    };

const validateSignup = (userName, firstName, lastName, password, verify, email, errors) => {
    errors.userNameError = "";
    errors.firstNameError = "";
    errors.lastNameError = "";
    errors.passwordError = "";
    errors.verifyError = "";
    errors.emailError = "";

    // Validate and sanitize
    if (!validator.isLength(userName, { min: 1, max: 20 }) || !validator.isAlphanumeric(userName)) {
        errors.userNameError = "Invalid user name (must be 1-20 alphanumeric characters).";
        return false;
    }

    if (!validator.isLength(firstName, { min: 1, max: 100 }) || !validator.isAlpha(firstName, 'en-US', { ignore: ' ' })) {
        errors.firstNameError = "Invalid first name.";
        return false;
    }

    if (!validator.isLength(lastName, { min: 1, max: 100 }) || !validator.isAlpha(lastName, 'en-US', { ignore: ' ' })) {
        errors.lastNameError = "Invalid last name.";
        return false;
    }

    if (!validator.isStrongPassword(password, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 0
    })) {
        errors.passwordError = "Password must be at least 8 characters with numbers, lowercase and uppercase letters.";
        return false;
    }

    if (password !== verify) {
        errors.verifyError = "Passwords do not match.";
        return false;
    }

    if (!validator.isEmail(email)) {
  return  false;    }

    return true;
};


        this.handleSignup = async (req, res, next) => {
    try {
        let {
            email,
            userName,
            firstName,
            lastName,
            password,
            verify
        } = req.body;

        // Sanitize inputs
        email = validator.normalizeEmail(email);
        userName = validator.escape(userName);
        firstName = validator.escape(firstName);
        lastName = validator.escape(lastName);

        const errors = { userName, email };

        // Validate user input
        if (!validateSignup(userName, firstName, lastName, password, verify, email, errors)) {
            console.log("Validation failed:", errors);
            return res.render("signup", { ...errors, environmentalScripts });
        }

        userDAO.getUserByUserName(userName, async (err, user) => {
            if (err) {
                console.error("DB error:", err);
                return next(err);
            }

            if (user) {
                errors.userNameError = "User name already in use. Please choose another";
                return res.render("signup", { ...errors, environmentalScripts });
            }

            // Hash password before storing
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

            // Add new user
            userDAO.addUser(userName, firstName, lastName, hashedPassword, email, (err, newUser) => {
                if (err) {
                    console.error("Error creating user:", err);
                    return next(err);
                }

                // Prepare user data
                prepareUserData(newUser, next);

                // 🔑 Regenerate session instead of sessionDAO
                req.session.regenerate((regenErr) => {
                    if (regenErr) {
                        console.error("Session regeneration error:", regenErr);
                        return next(regenErr);
                    }

                    req.session.userId = newUser._id;
                    newUser.userId = newUser._id;

                    // Set secure cookie using req.session.id
                    res.cookie("session", req.session.id, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === "production",
                        sameSite: "strict"
                    });

                    console.log("✅ User successfully signed up:", newUser.userName);

                    return res.render("dashboard", {
                        ...newUser,
                        environmentalScripts
                    });
                });
            });
        });

    } catch (error) {
        console.error("Unexpected error in signup:", error);
        return next(error);
    }
};

            
               

            

       
               
                   

    this.displayWelcomePage = (req, res, next) => {
        let userId;

        if (!req.session.userId) {
            console.log("welcome: Unable to identify user...redirecting to login");
            return res.redirect("/login");
        }

        userId = req.session.userId;

        userDAO.getUserById(userId, (err, doc) => {
            if (err) return next(err);
            doc.userId = userId;
            return res.render("dashboard", {
                ...doc,
                environmentalScripts
            });
        });
    };
}

module.exports = SessionHandler;
