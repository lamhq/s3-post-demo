
const cryptoJs = require('crypto-js')
const fs = require('fs')
const path = require('path')
const validate = require('validate.js')
const express = require('express')
const app = express()
const s3 = require('./s3')

// load content from template.html
var content = fs.readFileSync(path.resolve(__dirname, 'template.html'), 'utf8')

// replace param in content
var params = s3.getUploadParams()
var formatted = validate.format(content, params)

// save content to index.html
fs.writeFileSync(path.resolve(__dirname, 'index.html'), formatted, { encoding: 'utf8' })

// start server
app.use(express.static(path.resolve(__dirname)))
app.listen(4000)