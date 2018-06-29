const cryptoJs = require('crypto-js')

const defOptions = {
  accessKeyId: 'AKIAIIP4PGH4IS7KLYJQ',
  secretAccessKey: '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',
  bucket: 'lamhq',
  region: 'ap-southeast-1',
  service: 's3',
  duration: 10, // minutes
  // expiration: '2018-12-12T00:00:00.000Z',
  // date: '20181212',
  // keyPrefix: 'test/',
}

function getSignature(params) {
  const { region, service, secretAccessKey, date } = params
  var base64Policy = getStringToSign(params)
  var dateKey = cryptoJs.HmacSHA256(date, `AWS4${secretAccessKey}`)
  var regionKey = cryptoJs.HmacSHA256(region, dateKey)
  var serviceKey = cryptoJs.HmacSHA256(service, regionKey)
  var signatureKey = cryptoJs.HmacSHA256('aws4_request', serviceKey)
  return cryptoJs.HmacSHA256(base64Policy, signatureKey).toString(cryptoJs.enc.Hex)
}

function getStringToSign(params) {
  const { bucket, accessKeyId, region, service, expiration, date, keyPrefix } = params
  var policy = {
    expiration,
    conditions: [
      { bucket: bucket },
      { success_action_status: '200' },
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

/**
 * get form params for uploading to s3 using http post
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-post-example.html
 */
function getUploadParams() {
  const { accessKeyId, region, service, duration } = defOptions
  var expireAt = new Date()
  expireAt.setMinutes(expireAt.getMinutes()+duration)
  var date = expireAt.toISOString().substr(0, 10).replace(/-/g,'')

  var params = {
    ...defOptions,
    expiration: expireAt.toISOString(),
    date: date,
    keyPrefix: 'test/',
    ['x-amz-date']: `${date}T000000Z`,
    ['x-amz-credential']: `${accessKeyId}/${date}/${region}/${service}/aws4_request`,
  }

  return {
    keyPrefix: params.keyPrefix,
    acl: 'public-read',
    success_action_status: '200',
    policy: getStringToSign(params),
    ['x-amz-signature']: getSignature(params),
    ['x-amz-credential']: params['x-amz-credential'],
    ['x-amz-date']: params['x-amz-date'],
    ['x-amz-algorithm']: 'AWS4-HMAC-SHA256',
  }
}

module.exports = {
  getUploadParams
}
