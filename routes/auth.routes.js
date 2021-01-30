const {Router} = require('express');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router();

// /api/auth/register
router.post(
    '/register',
    [
      check('email', 'Invalid Email!').isEmail(),
      check('password', 'Minimal length of password should be 6 character!').isLength({min: 6})
    ],
    async (req, res) => {
    try {

        const errors = validationResult(req);

        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Invalid data at register!'
            })
        }

        const {email, password} = req.body;

        const candidate = await User.findOne({email})

        if (candidate) {
            return res.status(400).json({message: 'Such user already exists!'})
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({email, password: hashedPassword});

        await user.save();

        res.status(201).json({message: 'User was created successfully!'})
    } catch (e) {
        res.status(500).json({message: 'Something went wrong :('})
    }
})

 // /api/auth/login
 router.post(
     '/login',
     [
         check('email', 'Entre valid email!').normalizeEmail().isEmail(),
         check('password', 'Enter the password!').exists()
     ],
     async (req, res) => {
         try {
             const errors = validationResult(req);

             if(!errors.isEmpty()) {
                 return res.status(400).json({
                     errors: errors.array(),
                     message: 'Invalid data at login!'
                 })
             }

             const {email, password} = req.body;

             const user = await User.findOne({email});
             if(!user) {
                 return res.status(400).json({message:'User was not found!'})
             }

             const isMatch = await bcrypt.compare(password, user.password);

             if(!isMatch) {
                 return res.status(400).json({message: 'Invalid password! Try again.'})
             }

             const token = jwt.sign(
                 {userId: user.id},
                 config.get('jwtSecret'),
                 {expiresIn: '1h'}
             )

             res.json({token, userId: user.id});
         } catch (e) {
             res.status(500).json({message: 'Something went wrong :('})
         }
 })

module.exports = router;