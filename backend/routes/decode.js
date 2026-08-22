const express = require('express');
const multer = require('multer');
const Jimp = require('jimp');
const { BrowserMultiFormatReader, RGBLuminanceSource, BinaryBitmap, HybridBinarizer } = require('@zxing/library');
const { getVerdict } = require('../../security/verdictEngine');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/', upload.single('qrImage'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image uploaded' });
    }

    // Load image with Jimp
    const image = await Jimp.read(req.file.buffer);
    const { width, height } = image.bitmap;

    // Convert to grayscale luminance array for zxing
    const luminances = new Uint8ClampedArray(width * height);
    let idx = 0;
    image.scan(0, 0, width, height, function (x, y, i) {
      const gray = (this.bitmap.data[i] + this.bitmap.data[i + 1] + this.bitmap.data[i + 2]) / 3;
      luminances[idx++] = gray;
    });

    const luminanceSource = new RGBLuminanceSource(luminances, width, height);
    const binaryBitmap = new BinaryBitmap(new HybridBinarizer(luminanceSource));
    const reader = new BrowserMultiFormatReader();

    const result = reader.decode(binaryBitmap);
    const decodedUrl = result.getText();

    // Run security checks
    const verdictResult = await getVerdict(decodedUrl);

    res.json({
      decodedUrl,
      ...verdictResult,
    });
  } catch (err) {
    console.error('Decode error:', err.message);
    res.status(500).json({ error: 'Failed to decode QR code', details: err.message });
  }
});

module.exports = router;
