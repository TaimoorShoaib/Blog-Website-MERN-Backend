require("dotenv").config();

// getting-started.js
const mongoose = require('mongoose');
const { isUtf8 } = require('buffer');


async function dbConnect() {
  await mongoose.connect(`${process.env.CONNSTRING}`).then(() => {
    console.log("We are connected to the DataBase")
  }).catch((error) => {
    console.log(error)
  });

  // use `await mongoose.connect('mongodb://user:password@127.0.0.1:27017/test');` if your database has auth enabled
}

module.exports = dbConnect