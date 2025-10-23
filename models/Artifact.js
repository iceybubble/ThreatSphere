import mongoose from "mongoose";

const artifactSchema = new mongoose.Schema({
  filename: String,
  originalname: String,
  size: Number,
  mimetype: String,
  sha256: String,
  source: String,
  note: String,
  uploadedAt: Date,
});

const Artifact = mongoose.model("Artifact", artifactSchema);
export default Artifact;
