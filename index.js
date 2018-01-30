
const cryptoJs = require('crypto-js')
const fs = require('fs')
const path = require('path')
const validate = require('validate.js')
const express = require('express')
const app = express()
const crypto = require('crypto')

function hmacSHA256(data, key) {
  return crypto.createHmac('sha256', key)
    .update(data)
    .digest('hex')
}

/**
 * @param {Date} expireAt
 * @param {String} date string used to calculate the signature, format: yyyymmdd, ex: 20181224
 * @param {String} keyPrefix string that is prepend to object key, ex: folder/
 * @return {Object}
 */
function getSignature(params) {
  const { region, service, secretAccessKey, date } = { ...options, ...params }
  var base64Policy = getStringToSign(params)
  var dateKey = cryptoJs.HmacSHA256(date, `AWS4${secretAccessKey}`)
  var regionKey = cryptoJs.HmacSHA256(region, dateKey)
  var serviceKey = cryptoJs.HmacSHA256(service, regionKey)
  var signatureKey = cryptoJs.HmacSHA256('aws4_request', serviceKey)
  return cryptoJs.HmacSHA256(base64Policy, signatureKey).toString(cryptoJs.enc.Hex)
}

/**
 * @param {String} expiration
 * @param {String} date string used to calculate the signature, format: yyyymmdd, ex: 20181224
 * @param {String} keyPrefix string that is prepend to object key, ex: folder/
 * @return {Object}
 */
function getStringToSign(params) {
  const { bucket, accessKeyId, region, service, expiration, date, keyPrefix } = { ...options, ...params }
  const policy = {
    expiration,
    conditions: [
      { bucket: bucket },
      { success_action_status: "200" },
      ['starts-with', '$key', keyPrefix],
      {'acl': 'public-read'},
      ['starts-with', '$Content-Type', 'image/'],
      {'x-amz-algorithm': 'AWS4-HMAC-SHA256'},
      {'x-amz-credential': `${accessKeyId}/${date}/${region}/${service}/aws4_request`},
      {'x-amz-date': `${date}T000000Z` }
    ]
  }
  return new Buffer( JSON.stringify(policy), 'utf-8').toString('base64')
}

var options = {
  accessKeyId: 'AKIAJTG2L64AXHSPYIHA',
  secretAccessKey: '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',
  bucket: 'lamhq',
  region: 'ap-southeast-1',
  service: 's3',
  expiration: '2018-12-12T00:00:00.000Z',
  date: '20181212',
  keyPrefix: 'test/',
}

var expireAt = new Date()
expireAt.setMinutes(expireAt.getMinutes()+10)
var params = {
  expiration: expireAt.toISOString(),
  date: expireAt.toISOString().substr(0, 10).replace(/-/g,''),
  keyPrefix: 'test/'
}

// load content from template.html
var content = fs.readFileSync(path.resolve(__dirname, 'template.html'), 'utf8')

// replace param in content
var formatted = validate.format(content, {
  policy: getStringToSign(params),
  signature: getSignature(params),
  keyPrefix: params.keyPrefix,
  date: params.date,
  region: options.region,
  service: options.service,
  accessKeyId: options.accessKeyId
})

// save content to index.html
fs.writeFileSync(path.resolve(__dirname, 'index.html'), formatted, { encoding: 'utf8' })

// start server
app.use(express.static(path.resolve(__dirname)))
app.listen(4000)