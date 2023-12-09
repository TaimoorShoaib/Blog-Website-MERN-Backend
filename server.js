const express = require("express");
const path = require("path"); // Add this line to import the path module
require("dotenv").config();
const dbConnect = require("./database/index");
const router = require("./routes/index");
const errorHandler = require("./middlewares/errorhandler");
const app = express();
const port = process.env.PORT;
const cookieParser = require("cookie-parser");
const cors = require("cors");

const corsOption = {
  credentials: true,
  origin: ["http://localhost:3000"],
};

app.use(cookieParser());
app.use(cors(corsOption));
app.use(express.json({ limit: "50mb" }));

app.use(router);

dbConnect().catch((err) => console.log(err)); // Call the dbConnect function to establish the database connection

app.use("/storage", express.static("storage"));
//app.use(express.urlencoded())

app.use(errorHandler);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
