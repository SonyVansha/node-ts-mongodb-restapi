import express from 'express';
import { get, identity, merge } from 'lodash';

import { getUserBySessionToken } from '../db/users';

export const isOwner = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const { id } = req.params;
        const currentUser = get(req, 'identity.id') as string;

        if (!currentUser) {
            return res.status(403).send({ message: 'Missing session token' });
        }

        if (currentUser.toString() != id) {
            return res.status(403).send({ message: 'Unauthorized' });
        }

        next();
    } catch (error) {
        console.log(error);
        return res.sendStatus(400);
    }
}

export const isAuthenticated = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const sessionToken = req.cookies['SONY-AUTH'];

        if (!sessionToken) {
            return res.status(403).send({ message: 'Missing session token' });
        }

        const existingUser = await getUserBySessionToken(sessionToken);

        if (!existingUser) {
            return res.status(403).send({ message: 'Invalid session token' });
        }

        merge(req, { identity: existingUser });

        return next();
    } catch (error) {
        console.log(error);
        return res.sendStatus(400);
    }
}


