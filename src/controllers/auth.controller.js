import cloudinary from "../lib/cloudinary.js";
import { generateToken } from "../lib/utils.js";
import { protectRoute } from "../middleware/auth.middleware.js";
import User from "../models/user.model.js"
import bcrypt from "bcryptjs"

export const signup = async (req,res)=>{
    //logic for signup
    const {fullName,email,password} = req.body;
    try {
        // hash password  : use package bcrytjs
        // if user gives you 1234 as passward so we dont want to save it as 1234

        if(!fullName || !email || !password){
            return res.status(400).json({message : "Please fill all the fields"});
        }


        if(password.length<6){
            return res.status(400).json({message:"Password should be at least 6 characters long "});
        }

        const user = await User.findOne({email})

        if (user) return res.status(400).json({message : "Email is already in use "});
        // if user is not in database then we will create a new user

        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password,salt)

        // we will create a new user with hashed password
        const newUser = new User({
            fullName,
            email,
            password:hashedPassword
        })

        if(newUser){
            await newUser.save()

            // generate jwt token here 
            generateToken(newUser._id,res);

            res.status(201).json({
                _id:newUser._id,
                fullName:newUser.fullName,
                email:newUser.email,
                profilePic:newUser.profilePic,

            })
        }
        else{
            return res.status(400).json({message : "Failed to create new user "});
        }

      } catch (error) {
        console.log("Error in signup controller",error.message);
        res.status(500).json({message : "Internal server error "});
    }
}

export const login = async (req,res)=>{
    const {email,password}= req.body
    try {
        const user = await User.findOne({email})
        if(!user) {
            return res.status(400).json({message : "Invalid credentials"});
        }
        const isPasswordCorrect = await bcrypt.compare(password,user.password)
        if(!isPasswordCorrect){
            return res.status(400).json({message : "Invalid credentials"});
        }
        
        generateToken(user._id,res)

        res.status(200).json({
            _id:user._id,
            fullName:user.fullName,
            email:user.email,
            profilePic:user.profilePic,
        })

    } catch (error) {
        console.log("Error in login controller", error.message);
        res.status(500).json({message : "Internal server error "});
    }
}

export const logout = (req,res)=>{
    try {
        res.cookie("jwt","",{maxAge:0})
        res.status(200).json({message : "Logged out successfully"})
    } catch (error) {
        console.log("Error in logout controller", error.message);
        res.status(500).json({message : "Internal server error "});
    }
}

export const updateProfile =async (req,res)=>{
    try {
        const {profilePic}=req.body;
        const userId = req.user._id;

        if (!req.user || !req.user._id) {
            return res.status(401).json({ message: "Unauthorized" });
        }
        

        if(!profilePic){
            return res.status(400).json({message : "Please add a profile picture"});
        }

       const uploadResponse = await cloudinary.uploader.upload(profilePic)


       const updatedUser = await User.findByIdAndUpdate(userId,{profilePic : uploadResponse.secure_url},{new:true})

       res.status(200).json({message : "Profile updated successfully",updatedUser})
    } catch (error) {
      console.log("error in updating profile : ",error);
      res.status(500).json({message : "Internal server error "});
    }
}

export const checkAuth = (req,res)=>{
    try{
        res.status(200).json({message : "User is authenticated"})
        }catch(error){
            console.log("Error in checkAuth controller", error);
            res.status(500).json({message : "Internal server error "});
    }
}



