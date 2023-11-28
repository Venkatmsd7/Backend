import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import bodyParser from "body-parser"
import fileUpload from "express-fileupload"
const app=express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
    
}))

app.use(express.json({limit: "16000kb"}))
app.use(express.urlencoded())
app.use(express.static("public"))
app.use(cookieParser())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))
import userRouter from "./routes/user.routes.js"

app.use("/api/v1/users",userRouter)

export { app }