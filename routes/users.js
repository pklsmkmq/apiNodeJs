const express = require('express');
const router = express.Router();
const validator = require('fastest-validator');
const v = new validator();
const { Users } = require("../models");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const verifyToken = require('../middleware/verifyToken');

/* GET users listing. */
router.get("/", verifyToken, async (req, res) => {
  let user = await Users.findAll(
    {
      attributes: ["id", "name", "email"]
    }
  );

  return res.json({
    status: 200,
    message: "Success Menampilkan Data",
    data: user
  });
});

router.post('/register', async (req, res) => {
  const schema = {
    name: "string",
    email: "string",
    password: "string",
    confPassword: "string",
  };

  const validate = v.validate(req.body, schema);
  if (validate.length) {
    return res.status(400).json(validate);
  }

  const { name, email, password, confPassword } = req.body;
  if (password != confPassword) {
    return res.status(404).json({ status: 404, message: "Password dan Confirm Password tidak cocok" });
  }

  const salt = await bcrypt.genSalt();
  const hashPassword = await bcrypt.hash(password, salt);

  try {
    const userCreate = Users.create({
      name: name,
      email: email,
      password: hashPassword
    });
    return res.json({
      status: 201,
      message: "Registrasi Berhasil"
    });
  } catch (error) {
    return res.status(401).json({ status: 404, message: error });
  }
});

router.post('/login', async (req, res) => {
  const schema = {
    email: "string",
    password: "string"
  };

  const validate = v.validate(req.body, schema);
  if (validate.length) {
    return res.status(400).json(validate);
  }

  const data = await Users.findOne({
    where: {
      email: req.body.email
    },
  });
  const match = await bcrypt.compare(req.body.password, data.password);
  if (!match) {
    return res.status(401).json({ status: 401, message: "Wrong Password" });
  }

  const id = data.id;
  const name = data.name;
  const email = data.email;

  const accessToken = jwt.sign({ id, name, email }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "1d"
  });
  const refreshToken = jwt.sign({ id, name, email }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d"
  });

  await data.update({
    refresh_token: refreshToken
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    maxAge: 168 * 60 * 60 * 1000,
    // jika https
    // secure: true
  });

  return res.json({
    status: 200,
    message: "Login Berhasil",
    data: data,
    token: accessToken
  });
});

router.get('/authMe', async (req, res) => {
  try {
    const refresh_token = req.cookies.refreshToken;
    if (!refresh_token) {
      return res.status(401).json({ status: 401, message: "Missing Token" });
    }
    const data = await Users.findOne({
      where: {
        refresh_token: refreshToken
      }
    });
    if (!data) {
      return res.status(403).json({ status: 403, message: "Data Tidak Ditemukan" });
    }

    const id = data.id;
    const name = data.name;
    const email = data.email;

    const accessToken = jwt.sign({ id, name, email }, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: "1d"
    });

    return res.json({
      status: 200,
      message: "AuthMe Berhasil",
      data: data,
      token: accessToken
    });
  } catch (error) {
    return res.status(401).json({ status: 401, message: "AuthMe Fail" });
  }
});

router.delete('/logout', async (req, res) => {
  const refresh_token = req.cookies.refreshToken;
  if (!refresh_token) {
    return res.status(204).json({ status: 204, message: "Missing Token" });
  }

  const data = await Users.findOne({
    where: {
      refresh_token: refreshToken
    }
  });
  if (!data) {
    return res.status(204).json({ status: 204, message: "Data Tidak Ditemukan" });
  }

  const updateUser = data.update({
    refresh_token: null
  });
  res.clearCookie('refreshToken');
  return res.json({
    status: 200,
    message: "Logout Berhasil"
  });
});

module.exports = router;
