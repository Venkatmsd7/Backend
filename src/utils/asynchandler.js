const asynsHandler = (requestHandler) =>{
    (req,res,next) =>{
        Promise.resolve(requestHandler(res,req,next)).catch((err)=>next(err))
    }
}

export {asynsHandler}