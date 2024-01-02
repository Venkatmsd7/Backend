import { asyncHandler } from "../utils/asynchandler.js";
import { User } from "../models/user.model.js"; 
import { ApiError } from "../utils/ApiError.js";
import jwt from "jsonwebtoken";

export const verifyJwt=asyncHandler(async(req,res,next)=>{
    try {
        const token= req.cookies?.accessToken || req.header("Authoriztion")?.replace("Bearer ","")
    
        if(!token){
            throw new ApiError(401,"Unauthorized request")
        }
        
        const decodedToken=jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
    
        const user= User.findById(decodedToken?._id).select("-password -refreshToken");
    
        if(!user){
            throw new ApiError(401, "Invalid Access Token")
        }
    
        req.user=user;
        next()
    } catch (error) {
        throw new ApiError(401,error?.message||"Invalid access token")
    }
})