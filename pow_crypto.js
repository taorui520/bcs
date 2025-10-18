/**
 * 实践 POW， 编写程序用自己的昵称 + nonce，不断修改nonce 进行 sha256 Hash 运算
 * 直到满足 4 个 0 开头的哈希值，打印出花费的时间、Hash 的内容及Hash值。
 * 再次运算直到满足 5 个 0 开头的哈希值，打印出花费的时间、Hash 的内容及Hash值。
 */

const crypto = require('crypto');

function powCalc(difficulty) {
  let nonce = 0, nickName = "torys";
  const startTime = Date.now();
  while(true){
    const hash = crypto.createHash('sha256');
    const content = nickName + nonce;
    hash.update(content);
    const hashValue = hash.digest('hex');

    if (hashValue.startsWith('0'.repeat(difficulty))) {
      const endTime = Date.now();
      const timeSpent = (endTime - startTime) / 1000; // 转换为秒
      console.log(`Difficulty: ${difficulty}, Content: ${content}, Hash: ${hashValue}, Time spent: ${timeSpent} seconds`);
      return { content, hashValue, timeSpent };
    }
    nonce++;
  }
}

module.exports = { powCalc };

// 测试代码 (取消注释上面的两行即可运行测试)
// if (require.main === module) {
//   powCalc(4);
//   powCalc(5);
// }

/**
 * 实践非对称加密 RSA：
 * 先生成一个公私钥对
 * 用私钥 对符合 POW 4 个 0 开头的哈希值的 “昵称 + nonce” 进行私钥签名
 * 用公钥验证签名的有效性
 */
const { generateKeyPairSync, sign, verify } = require('crypto');

function rsaSignAndVerify(data) {   
    // 生成公私钥对 
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'   
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'   
        }   
    });
    // 用私钥对数据进行签名
    const signer = sign('sha256', Buffer.from(data), {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    });
    // 用公钥验证签名
    const isVerified = verify('sha256', Buffer.from(data), {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,    
    }, signer);

    console.log(`Data: ${data}`);
    console.log(`Signature: ${signer.toString('hex')}`);
    console.log(`Verification result: ${isVerified}`);
    return isVerified;
}
module.exports.rsaSignAndVerify = rsaSignAndVerify;

// 测试代码 (取消注释上面的两行即可运行测试)        
if (require.main === module) {
    const powResult = powCalc(4);
    rsaSignAndVerify(powResult.content);
}






