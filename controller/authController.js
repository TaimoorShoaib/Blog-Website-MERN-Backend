const Joi = require("joi");
const User = require("../models/user");
const userDto = require("../dto/user");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const JWTService = require("../services/JWTService");
const userDTO = require("../dto/user");
const RefreshToken = require("../models/token");
const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,25}$/;
const authController = {
  async register(req, res, next) {
    // 1. validate user input
    /* const userRegisterSchema = Joi.object({
          username: Joi.string().min(5).max(30).required(),
          name: Joi.string().max(30).required(),
          email: Joi.string().email().required(),
          password: Joi.string().pattern(passwordPattern).required(),
          confirmPassword: Joi.ref("password"),
        });
        const { error } = userRegisterSchema.validate(req.body);
    
        // 2. if error in validation -> return error via middleware
        if (error) {
          return next(error);
        }
    
        // 3. if email or username is already registered -> return an error
    
        try {
          const emailInUse = await User.exists({ email });
    
          const usernameInUse = await User.exists({ username });
    
          if (emailInUse) {
            const error = {
              status: 409,
              message: "Email already registered, use another email!",
            };
    
            return next(error);
          }
    
          if (usernameInUse) {
            const error = {
              status: 409,
              message: "Username not available, choose another username!",
            };
    
            return next(error);
          }
        } catch (error) {
          return next(error);
        }*/

    try {
      const userRegisterSchema = Joi.object({
        username: Joi.string().min(5).max(30).required(),
        name: Joi.string().max(30).required(),
        email: Joi.string().email().required(),
        password: Joi.string().pattern(passwordPattern).required(),
        confirmPassword: Joi.ref("password"),
      });
      const { error } = userRegisterSchema.validate(req.body);

      // 2. if error in validation -> return error via middleware
      if (error) {
        return next(error);
      }
      const { username, name, email, password } = req.body;

      // 4. password hash
      const hashedPassword = await bcrypt.hash(password, 10);

      // save the data in the database
      let accesToken;
      let refreshToken;
      let user;
      try {
        const userToRegister = new User({
          username,
          email,
          name,
          password: hashedPassword,
        });
        user = await userToRegister.save();
        // token generation
        accesToken = JWTService.signAccessToken({ _id: user._id }, "30m");
        refreshToken = JWTService.signRefreshToken({ _id: user._id }, "60m");
      } catch (err) {
        const error = {
          status: 409,
          message:
            "UserName or Email not available, choose another UserName or Email!",
        };
        return next(error);
      }
      // store refresh token in db
      await JWTService.storeRefreshToken(refreshToken, user._id);
      // send  token in cookies
      res.cookie("accessToken", accesToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
      res.cookie("refreshToken", refreshToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });

      // send the res to the user and give it
      const userDto = new userDTO(user);
      return res.status(201).json({ user: userDto, auth: true });
    } catch (err) {
      const error = {
        status: 409,
        message:
          "UserName or Email not available, choose another UserName or Email!",
      };
      return next(error);
    }
  },
  async login(req, res, next) {
    const userLoginSchema = Joi.object({
      email: Joi.string().min(5).email().required(),
      password: Joi.string().pattern(passwordPattern).required(),
    });
    const { error } = userLoginSchema.validate(req.body);

    // 2. if error in validation -> return error via middleware
    if (error) {
      return next(error);
    }
    try {
      const email = req.body.email;
      const password = req.body.password;

      const user = await User.findOne({ email: email });
      if (user) {
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
          const accessToken = JWTService.signAccessToken(
            { _id: user._id },
            "30m"
          );
          const refreshToken = JWTService.signRefreshToken(
            { _id: user._id },
            "60m"
          );

          // update refresh token
          try {
            await RefreshToken.updateOne(
              {
                _id: user._id,
              },
              { token: refreshToken },
              { upsert: true }
            );
          } catch (error) {
            return next(error);
          }
          res.cookie("accessToken", accessToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
          });
          res.cookie("refreshToken", refreshToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
          });

          const userDto = new userDTO(user);
          res.status(200).json({ user: userDto, auth: true });
        } else {
          res.status(400).json({ message: "Invalid Credential" });
        }
      } else {
        res.status(400).json({ message: "Invalid Credential" });
      }
    } catch (error) {
      return next(error);
    }
    let accessToken;
    let refreshToken;
  },
  async logout(req, res, next) {
    // DElete the refresh token
    const refreshToken = req.cookies.refreshToken;
    try {
      await RefreshToken.deleteOne({ token: refreshToken });
    } catch (error) {
      return next(error);
    }
    // delete cookie
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    // response
    res.status(200).json({ user: null, auth: false });
  },
  async refresh(req, res, next) {
    // get  refreshtoken form the cookies
    const originalRefreshToken = req.cookies.refreshToken;

    let id;
    try {
      id = JWTService.verifyRefreshToken(originalRefreshToken)._id;
    } catch (e) {
      const error = {
        status: 401,
        message: "unauthorized",
      };
      return next(error);
    }
    // verify refresh token
    try {
      const match = RefreshToken.findOne({
        _id: id,
        token: originalRefreshToken,
      });
      if (!match) {
        const error = {
          status: 401,
          message: "unauthorized",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    // generate new refresh token
    try {
      const accessToken = JWTService.signAccessToken({ _id: id }, "30m");
      const refreshToken = JWTService.signRefreshToken({ _id: id }, "60m");
      // update the db
      await RefreshToken.updateOne({ _id: id }, { token: refreshToken });
      res.cookie("accessToken", accessToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
      res.cookie("refreshToken", refreshToken, {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
      });
    } catch (error) {
      return next(error);
    }

    //return response
    const user = await User.findOne({ _id: id });
    const userDto = new userDTO(user);
    return res.status(200).json({ user: userDto, auth: true });
  },
};

module.exports = authController;
