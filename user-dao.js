const bcrypt = require("bcrypt");

/* The UserDAO must be constructed with a connected database object */
function UserDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof UserDAO)) {
        console.log("Warning: UserDAO constructor called without 'new' operator");
        return new UserDAO(db);
    }

    const usersCol = db.collection("users");

    this.addUser = async (userName, firstName, lastName, password, email, callback) => {
        try {
            const hashedPassword = await bcrypt.hash(password, 10);

            // Create user document
            const user = {
                userName,
                firstName,
                lastName,
                benefitStartDate: this.getRandomFutureDate(),
                password: hashedPassword
            };

            // Add email if set
            if (email) {
                user.email = email;
            }

            // Get next sequence id
            this.getNextSequence("userId", (err, id) => {
                if (err) {
                    return callback(err, null);
                }

                user._id = id;

                // Insert into collection
                usersCol.insertOne(user, (err, result) => {
                    if (err) return callback(err, null);
                    callback(null, result.ops ? result.ops[0] : user);
                });
            });

        } catch (err) {
            // This catches any error from bcrypt.hash or insertOne
            callback(err, null);
        }
    };

    this.getRandomFutureDate = () => {
        const today = new Date();
        const day = (Math.floor(Math.random() * 10) + today.getDay()) % 29;
        const month = (Math.floor(Math.random() * 10) + today.getMonth()) % 12;
        const year = Math.ceil(Math.random() * 30) + today.getFullYear();
        return `${year}-${("0" + month).slice(-2)}-${("0" + day).slice(-2)}`;
    };

    this.validateLogin = (userName, password, callback) => {
        // Helper function to compare passwords
        const comparePassword = (fromDB, fromUser) => {
            return fromDB === fromUser;
            /*
            // Fix for A2-Broken Auth
            // compares decrypted password stored in this.addUser()
            return bcrypt.compareSync(fromDB, fromUser);
          */
        };

        // Callback to pass to MongoDB that validates a user document
        const validateUserDoc = (err, user) => {
            if (err) return callback(err, null);

            if (user) {
                if (comparePassword(password, user.password)) {
                    callback(null, user);
                } else {
                    const invalidPasswordError = new Error("Invalid password");
                    invalidPasswordError.invalidPassword = true;
                    callback(invalidPasswordError, null);
                }
            } else {
                const noSuchUserError = new Error("User: " + userName + " does not exist");
                noSuchUserError.noSuchUser = true;
                callback(noSuchUserError, null);
            }
        };

        usersCol.findOne({ userName: userName }, validateUserDoc);
    };

    this.getUserById = (userId, callback) => {
        usersCol.findOne({ _id: parseInt(userId) }, callback);
    };

    this.getUserByUserName = (userName, callback) => {
        usersCol.findOne({ userName: userName }, callback);
    };

    this.getNextSequence = (name, callback) => {
        db.collection("counters").findAndModify(
            { _id: name },
            [],
            { $inc: { seq: 1 } },
            { new: true },
            (err, data) => {
                if (err) return callback(err, null);

                if (!data || !data.value) {
                    return callback(new Error("Counter not found for " + name), null);
                }

                return callback(null, data.value.seq);
            }
        );
    };
}

module.exports = { UserDAO };

