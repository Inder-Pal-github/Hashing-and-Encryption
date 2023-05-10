// Using bcrypt library

const bcrypt = require("bcrypt");

const password = "my-password-to-gmail"

const hashedPassword = bcrypt.hashSync(password,10);
// every hash generate is always unique => same data to same hash value

console.log("Your hashed password:  ",hashedPassword);

const passwordByUser = "my-password-to-facebook";

const checkPassword = bcrypt.compareSync(passwordByUser,hashedPassword);

console.log(checkPassword?"Password is correct":"Password is incorrect");



/// Using crypto module

const crypto = require("crypto");

const myPassword = "password123"

const hashUsingCrypto = crypto.createHash("sha256").update(myPassword).digest("base64");

// console.log("Hashed password using crypto: ",hashUsingCrypto);

const userProvidedPassword = "password123"
const checkPassword = crypto.createHash("sha256").update(userProvidedPassword).digest("base64");

console.log(checkPassword===hashUsingCrypto);
