import express from "express";
import dotenv from "dotenv";
import cookieParser from 'cookie-parser'

import {connectDB} from "./lib/db.js"
import authRoutes from "./routes/auth.route.js";
import { connect } from "mongoose";

dotenv.config()
const app = express();
const PORT = process.env.PORT;

app.use(express.json());
app.use(cookieParser());


//1st route for authentication
app.use("/api/auth",authRoutes)

app.listen(PORT,()=>{
    console.log("server is running on port : ",PORT);
    connectDB()
});