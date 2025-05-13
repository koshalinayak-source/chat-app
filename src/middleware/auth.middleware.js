import jwt from "jsonwebtoken"
import User from "../models/User.js"

export const protectRoute = async (req, res, next) =>{
    try {
       const token = req.cookie.jwt
        if(!token) {
            return res.status(401).json({msg: "Please login to access"});
        }
        //now we will use package cookie-parser
        const decoded = jwt.verify(token,process.env.JWT_SECRET)
        if(!decoded){
            return res.status(401).json({msg: "Unauthorized - Invalid Token"});
        }

        const user = await User.findById(decoded.userId).select("-password");

        if(!user){
            return res.status(404).json({message:"User not found"});
        }

        req.user = user

        next()

    } catch (error) {
        console.log("Error inprotective middleware", error.message);
        res.status(500).json({msg: "Internal Server Error"})
    }
}