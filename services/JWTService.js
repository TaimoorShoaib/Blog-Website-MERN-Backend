const jwt = require('jsonwebtoken')
require("dotenv").config();
const RefreshToken = require('../models/token')

class JWTService {
    // sign access token
    static signAccessToken(payload,expiryTime){
        return jwt.sign(payload,process.env.PASS_CODE,{expiresIn:expiryTime})
    }
    // sign refresh token
    static signRefreshToken(payload,expiryTime){
        return jwt.sign(payload,process.env.PASS_CODE,{expiresIn:expiryTime})
    }
    // verify access token
    static verifyAccessToken(token){
        return jwt.verify(token,process.env.PASS_CODE)
    }
    // verify refresh token
    static verifyRefreshToken(token){
        return jwt.verify(token,process.env.PASS_CODE)
    }
    // store refresh token
    static async storeRefreshToken(token,userId){
        try{
            const newToken = new RefreshToken({
                token:token,
                userId:userId
              })
              // store in db
              await newToken.save()
        }
        catch(error){
            console.log(error)
        }
    }
}
module.exports = JWTService;
