import { Keypair, Connection, clusterApiUrl, PublicKey, LAMPORTS_PER_SOL, Transaction, SystemProgram } from '@solana/web3.js'
import axios from 'axios'
import nacl from 'tweetnacl'
import bs58 from 'bs58'


function signAndEncodeSignature(privateKeyBase58: any, timestamp: any) {
    const privateKey = bs58.decode(privateKeyBase58)
    const keypair = nacl.sign.keyPair.fromSecretKey(privateKey)
    const message = new TextEncoder().encode(`Sign in to pump.fun: ${timestamp}`)
    // const message = `Sign in to pump.fun: ${timestamp}`
    const signature = nacl.sign.detached(message, keypair.secretKey)

    if (!nacl.sign.detached.verify(message, signature, keypair.publicKey)) {
        throw new Error('Signature verification failed')
    }

    return {
        timestamp,
        signature: bs58.encode(signature),
        publicKey: bs58.encode(keypair.publicKey)
    }
}

// Function to perform login
async function performLogin(wallet: any) {
    try {
        const timestamp = Date.now().toString()
        const { signature } = signAndEncodeSignature(
            bs58.encode(wallet.secretKey),
            timestamp
        )

        const payload = {
            address: wallet.publicKey.toString(),
            signature: signature,
            timestamp: timestamp
        }

        const response = await axios.post(
            'https://frontend-api.pump.fun/auth/login',
            payload,
            {
                headers: {
                    Accept: '*/*',
                    'Content-Type': 'application/json',
                    Origin: 'https://pump.fun',
                    'User-Agent':
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                    'sec-ch-ua':
                        '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"'
                }
            }
        )

        if (response.headers['set-cookie']) {
            const authCookie = response.headers['set-cookie'].find((cookie: any) =>
                cookie.startsWith('auth_token=')
            )
            return authCookie ? authCookie.split('=')[1].split(';')[0] : null
        }
        console.log("Perform Login: ", response.status);
        return null
    } catch (error: any) {
        console.error('Login error:', error.message)
        throw error
    }
}

// Function to get token
async function getToken(walletPublicKey: any, authToken: any) {
    try {
        const response = await axios.get(
            `https://frontend-api.pump.fun/token/generateTokenForThread?user=${walletPublicKey}`,
            {
                headers: {
                    accept: 'application/json',
                    Cookie: `auth_token=${authToken}`,
                    'User-Agent':
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
                }
            }
        )
        console.log('token: ', response.data.token);
        return response.data.token
    } catch (error: any) {
        console.error('Token error:', error.message)
        throw error
    }
}

async function postCommentWithProxy(token: any, mint: any, text: any) {

    try {
        const response = await axios.post(
            'https://client-proxy-server.pump.fun/comment',
            { text, mint },
            {
                headers: {
                    accept: '*/*',
                    'content-type': 'application/json',
                    origin: 'https://pump.fun',
                    referer: 'https://pump.fun/',
                    'x-aws-proxy-token': token,
                    'User-Agent':
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
                },
                // httpsAgent: user.currentProxy.agent,
                proxy: false,
                validateStatus: (status: any) =>
                    status === 200 || status === 201 || status === 429 // Aceitar 200, 201 e 429
            }
        )

        return response.status === 200 || response.status === 201
    } catch (error) {
        console.log(error)
        throw error
    }
}

async function mainFunc() {
    const commentWallet = Keypair.generate()
    const authToken = await performLogin(commentWallet)
    if (!authToken) throw new Error('Failed to login')

    const token = await getToken(
        commentWallet.publicKey.toString(),
        authToken
    )
    if (!token) throw new Error('Failed to get token')

    console.log("token: ", token)

    let success = await postCommentWithProxy(
        token,
        "8u4QzAEwvxY1PZQF5EmZu9NtsMufinqG45SVnWivpump",
        "Hello, this is test",
    )
}

mainFunc();