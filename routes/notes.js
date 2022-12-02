const express = require('express');
const router = express.Router();
const validator = require('fastest-validator');
const v = new validator();
const { Notes } = require("../models");

router.get("/", async (req, res) => {
    let note = await Notes.findAll();

    return res.json({
        status: 200,
        message: "Success Menampilkan Data",
        data: note
    });
});

router.get('/:id', async (req, res) => {
    const id = req.params.id;
    let note = await Notes.findByPk(id);
    if (!note) {
        return res.status(404).json({ status: 404, message: "Data not found" });
    }

    return res.json({
        status: 200,
        message: "Success Menampilkan Data",
        data: note
    });
});

router.post('/', async (req, res) => {
    const schema = {
        title: "string",
        description: "string|optional"
    };

    const validate = v.validate(req.body, schema);
    if (validate.length) {
        return res.status(400).json(validate);
    }

    const note = await Notes.create(req.body);
    return res.json({
        status: 200,
        message: "Success create data",
        data: note
    });
});

router.put("/:id", async (req, res) => {
    const id = req.params.id;
    let note = await Notes.findByPk(id);
    if (!note) {
        return res.status(404).json({ status: 404, message: "Data not found" });
    }
    note = await note.update(req.body);
    res.json({
        status: 200,
        message: "Success update data",
        data: note,
    });
});

// DELETE
router.delete("/:id", async (req, res, next) => {
    const id = req.params.id;
    // check id in table note
    let note = await Notes.findByPk(id);
    if (!note) {
        return res.status(404).json({ status: 404, message: "Data not found" });
    }

    // proses delete data
    await note.destroy();
    res.json({
        status: 200,
        message: "Success delete data",
    });
});

module.exports = router;