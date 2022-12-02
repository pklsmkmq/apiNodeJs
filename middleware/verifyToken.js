const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    console.log(req.headers['authorization']);
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.status(401).json({ status: 403, message: "Missing Token" });
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) =>{
        if (err) {
            return res.status(401).json({ status: 403, message: "Wrong Token" });
        }
        req.email = decoded.email;
        next();
    })
}

module.exports = verifyToken;