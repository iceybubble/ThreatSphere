import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import Artifact from "../models/Artifact.js";

const router = express.Router();

// Configure upload folder
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Configure multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  },
});

const upload = multer({ storage });

// POST /upload
router.post("/", upload.single("file"), async (req, res) => {
  const apiKey = req.header("X-API-KEY");
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(403).json({ error: "Invalid API Key" });
  }

  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    const artifact = new Artifact({
      filename: req.file.filename,
      originalname: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype,
      source: req.body.source || "unknown",
      note: req.body.note || "",
      sha256: req.body.sha256 || null,
      uploadedAt: new Date(),
    });

    await artifact.save();

    res.status(200).json({
      status: "ok",
      id: artifact._id,
      filename: req.file.filename,
    });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
