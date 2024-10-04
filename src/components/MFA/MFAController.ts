import { NextFunction, Request, Response, Router } from 'express';
import { ReasonPhrases, StatusCodes } from 'http-status-codes';
import BaseController from '../BaseController';
import ApiError from '../../abstractions/ApiError';
import { IQRGnerateResponse, IUserInfo, IUserSatatus } from './MultiFactorAuthTypes';
import { MultiFactorAuthService } from './MultiFactorAuthService';
import { RouteDefinition } from '../../types/RouteDefinition';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({
	path: path.join(__dirname, '../../.env'),
});
/**
 * Multi Factor Auth controller
 */
export default class MultiFactorAuthController extends BaseController {
	// base path
	public basePath: string = 'mfa';
	private mfa: MultiFactorAuthService;

	constructor() {
		super();
		this.mfa = new MultiFactorAuthService();
	}

	/**
	 *
	 */
	// public register(): Router {
	// 	this.router.post('/ready', this.ready.bind(this));
	// 	this.router.post('/generate', this.generate.bind(this));
	// 	this.router.post('/verify', this.verify.bind(this));
	// 	this.router.post('/validate', this.validate.bind(this));
	// 	this.router.post('/reset', this.reset.bind(this));
	// 	return this.router;
	// }

    public routes(): RouteDefinition[] {
		return [
			{ path: '/ready', method: 'post', handler: this.ready.bind(this) },
			{
				path: '/generate',
				method: 'post',
				handler: this.generate.bind(this),
			},
			{
				path: '/verify',
				method: 'post',
				handler:  this.verify.bind(this),
			},
			{
				path: '/validate',
				method: 'post',
				handler: this.validate.bind(this),
			},
			{
				path: '/create',
				method: 'post',
				handler: this.create.bind(this),
			},
			{ path: '/reset', method: 'post', handler: this.reset.bind(this) },
		];
	}

	/**
	 *
	 * @param req
	 * @param res
	 * @param next
	 */
	public async ready(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { id } = req.body;
			if (!id) {
				throw new ApiError(ReasonPhrases.BAD_REQUEST, StatusCodes.BAD_REQUEST);
			}
			const response: IUserSatatus = await this.mfa.getMfaRecordById(id)
			res.locals.data = response;
			// call base class method	
			super.send(res);
		} catch (err) {
			next(err);
		}
	}

	/**
	 *
	 * @param req
	 * @param res
	 * @param next
	 */
	public async generate(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {

			const { id } = req.body;
			if (!id) {
				throw new ApiError(ReasonPhrases.BAD_REQUEST, StatusCodes.BAD_REQUEST);
			}
			const response: IQRGnerateResponse = await this.mfa.generateQRcode(id)
			res.locals.data = response;
			// call base class method	
			super.send(res);
		} catch (err) {
			next(err);
		}
	}


	/**
	 *
	 * @param req
	 * @param res
	 * @param next
	 */
	public async verify(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { secret, otp, id } = req.body;
			const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

			if (!otp || !secret || !id) {
				throw new ApiError(ReasonPhrases.BAD_REQUEST, StatusCodes.BAD_REQUEST);
			}

			if (!ENCRYPTION_KEY) {
				throw new ApiError(ReasonPhrases.INTERNAL_SERVER_ERROR, StatusCodes.INTERNAL_SERVER_ERROR);
			}

			const isVerified: boolean = this.mfa.verifyTOTP(secret, otp);

			if (isVerified) {
				const code: string = await this.mfa.generateBackupCode();
				const record: IUserInfo = {
					code,
					secret,                           
					id
				}
				const isActive: boolean = await this.mfa.saveMfaRecord(record, ENCRYPTION_KEY)
				res.locals.data = {
					code,
					isActive
				};
				super.send(res);
			}

			throw new ApiError("Invalid OTP", StatusCodes.UNAUTHORIZED, ReasonPhrases.UNAUTHORIZED);
		} catch (err) {
			next(err);
		}
	}


	/**
	 *
	 * @param req
	 * @param res
	 * @param next
	 */
	public async validate(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { otp, id } = req.body;
			const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

			if (!otp || !id) {
				throw new ApiError(ReasonPhrases.BAD_REQUEST, StatusCodes.BAD_REQUEST);
			}
			if (!ENCRYPTION_KEY) {
				throw new ApiError(ReasonPhrases.INTERNAL_SERVER_ERROR, StatusCodes.INTERNAL_SERVER_ERROR);
			}

			const secret: string = await this.mfa.getOtpSecretById(id, ENCRYPTION_KEY)

			const verified: boolean = this.mfa.verifyTOTP(secret, otp);
			res.locals.data = {
				verified
			};
			super.send(res);
		} catch (err) {
			next(err);  
		}
	}


	/**
	 *
	 * @param req
	 * @param res
	 * @param next
	 */
	public async reset(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { code, id } = req.body;
			if (!code || !id) {
				throw new ApiError(ReasonPhrases.BAD_REQUEST, StatusCodes.BAD_REQUEST);
			}

			const isReset = await this.mfa.reset(id, code);

			res.locals.data = {
				isReset
			};

			// call base class method
			super.send(res);
		} catch (err) {
			next(err);
		}
	}

    /**
	 *
	 * @param req
	 * @param res
	 * @param next
	 */
	public async create(
		req: Request,
		res: Response,
		next: NextFunction,
	): Promise<void> {
		try {
			const { id, isActive, hashBackupCode,encryptedSecret } = req.body;
			const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

			if (!id || !isActive || !hashBackupCode) {
				throw new ApiError(ReasonPhrases.BAD_REQUEST, StatusCodes.BAD_REQUEST);
			}


			if (!ENCRYPTION_KEY) {
				throw new ApiError(ReasonPhrases.INTERNAL_SERVER_ERROR, StatusCodes.INTERNAL_SERVER_ERROR);
			}

			const isVerified:any = this.mfa.create({ id, isActive, hashBackupCode,encryptedSecret });

            if(isVerified){
                let res:any = {message : 'Inserted data'}
                this.send(res)
            }
            
            throw new ApiError("Invalid OTP", StatusCodes.UNAUTHORIZED, ReasonPhrases.UNAUTHORIZED);
		} catch (err) {
			next(err);
		}
	}

}