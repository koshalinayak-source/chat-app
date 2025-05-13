
import jwt from "jsonwebtoken"

export const generateToken= (userId,res) =>{

    //generating a token 
    const token = jwt.sign({userId},process.env.JWT_SECRET,{
        expiresIn: "7d"
    })

    //returning the token to the user
    res.cookie("jwt",token,{
        maxAge: 7*24*60*60*1000, // MS
        httpOnly: true, // Prevents JavaScript from accessing the cookie (prevent XSS attacks)
        sameSite:"strict", // Prevents CSRF attacks
        secure: process.env.NODE_ENV !=="development"
    })

    return token;
}