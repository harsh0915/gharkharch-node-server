import jwt from "jsonwebtoken"
import crypto from "crypto"
import { insertToken } from "./database.js"

export async function generateTokens(user_name) {
	const payload = { username: user_name }
	/*a refresh token is a one-time-issued secret credential
	that can later be exchanged for new access tokens, 
	and in the process it is typically rotated and replaced,
	which is why it’s called a refresh token.*/
	const refresh_token = crypto.randomBytes(32).toString('hex')
	try {
		const all_good = await insertToken(refresh_token, user_name)
		if (all_good == 1) {
			//the SECRET is used to sign the jwt token so that no other un-authorised person
			//can change the details of a token
			const access_token = jwt.sign(payload, process.env.SECRET, { expiresIn: '15m' })
			return { refresh_token, access_token }
		} else {
			return null
		}
	}
	catch (e) {
		console.log(`Something went wrong while generating tokens : ${e.message}`)
	}
}

export async function generateAccesToken(user_name) {
	const payload = { username: user_name }
	try {
		const access_token = jwt.sign(payload, process.env.SECRET, { expiresIn: '15m' })
		return access_token
	}
	catch (e) {
		console.log(`Something went wrong while generating the access token : ${e.message}`)
	}
}
