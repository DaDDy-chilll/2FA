const express = require("express");
const speakeasy = require("speakeasy");
const uuid = require("uuid");
const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");
const app = express();
const PORT = process.env.PORT || 3000;

const db = new JsonDB(new Config("myDatabase", true, false, "/"));

app.use(express.json())

app.get("/", (req, res) => {
  res.json({ success: true });
});

//register user  and create temp secret
app.post('/api/register',(req,res) => {
    const id = uuid.v4();
    try {
        const path = `/user/${id}`
        const temp_secret = speakeasy.generateSecret()
        db.push(path,{id,temp_secret})
        res.json({id,secret:temp_secret.base32})
    } catch (error) {
        console.log(error);
        res.status(500).json({message:'error generating secrete'})
    }
})

//verify token and make secret perm

app.post('/api/verify', async (req,res) => {
    const {token,userId} = req.body
    try {
        const path = `/user/${userId}`
        const user = await db.getData(path);
        const {base32:secret} =  user.temp_secret

        const verified = speakeasy.totp.verify({secret,encoding:'base32',token})
        if(verified){
            db.push(path,{id:userId,secret:user.temp_secret})
            res.json({verified:true})
        }else{
            res.json({verified:false})
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({message:'error finding user'})
    }
})

//validate token

app.post('/api/validate', async (req,res) => {
    const {token,userId} = req.body
    try {
        const path = `/user/${userId}`
        const user = await db.getData(path);
        const {base32:secret} =  user.secret

        const tokenValidates = speakeasy.totp.verify({secret,encoding:'base32',token,window:1})
        if(tokenValidates){
            res.json({validated:true})
        }else{
            res.json({validated:false})
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({message:'error finding user'})
    }
})


app.listen(PORT, () => console.log(`server is running on port:${PORT}`));
