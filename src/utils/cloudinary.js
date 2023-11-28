import {v2} from "cloudinary";
import fs from "fs";

import {v2 as cloudinary} from 'cloudinary';
          
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const uploadOnCloudinary = async (localFilepath) => {
    try {
        
        if (!localFilepath) return null
        const response=await cloudinary.uploader.upload(localFilepath,{
            resource_type:"auto"
        })
        fs.unlinkSync(localFilepath)
        return response;
    } catch (error) {
        
        fs.unlinkSync(localFilepath) //remove the file as the upload failed
    }
} 


export default uploadOnCloudinary