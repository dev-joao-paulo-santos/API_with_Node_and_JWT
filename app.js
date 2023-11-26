require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const User = require('./models/User')

//password cloud mongodb: tVU4F92rtZeZCJCT
//ip e description: 200.52.30.121/32 My IP Address

app.get('/', (req, res) => {
    res.status(200).json({ mensagem: 'Bem vindo!' })
})

//Rota Privada
app.get("/user/:id", checkToken, async(req, res)=>{
    const id = req.params.id
    const user = await User.findById(id, '-password')

    if(!user)return res.status(404).json({mensagem: "Usuário não encontrado!"})

    res.status(200).json({user})
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token)return res.status(401).json({mensagem: "Acesso negado!"})

    try{

        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    }catch(error){
        res.status(400).json({mensagem: "Token inválido!"})
    }
}

app.post('/auth/register', async (req, res) => {

    const { nome, email, senha, telefones = { numero, ddd } } = req.body

    if (!nome) return res.status(422).json({ mensagem: 'O nome é obrigatório' })
    if (!email) return res.status(422).json({ mensagem: 'O email é obrigatório' })
    if (!senha) return res.status(422).json({ mensagem: 'A senha é obrigatória' })
    if (!telefones) return res.status(422).json({ mensagem: 'O telefone é obrigatório' })

    const userExiste = await User.findOne({ email: email })

    if (userExiste) return res.status(422).json({ mensagem: 'E-mail já existente' })

    const salt = await bcrypt.genSalt(12)
    const passHash = await bcrypt.hash(senha, salt)

    const user = new User({
        nome, email, senha: passHash, telefones
    })
    try {

        await user.save()
        res.status(201).json({ mensagem: 'Usuário criado com sucesso!' })

    } catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro no servidor! Por favor tente mais tarde." })
        res.status(500).json({ mensagem: error })

    }
})

//login
app.post('/auth/login', async (req, res) => {

    const { email, senha } = req.body
    if (!email) return res.status(422).json({ mensagem: 'O email é obrigatório' })
    if (!senha) return res.status(422).json({ mensagem: 'A senha é obrigatória' })

    const user = await User.findOne({ email: email })

    if (!user) return res.status(404).json({ mensagem: 'Este usuário não está cadastrado!' })

    //verificar senha
    const checkPass = await bcrypt.compare(senha, user.senha)

    if (!checkPass) return res.status(422).json({ mensagem: "Senha incorreta!" })

    try {

        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )
        res.status(200).json({mensagem: 'Autenticação realizada com sucesso!', token})

    }
    catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro no servidor! Por favor tente mais tarde." })
        res.status(500).json({ mensagem: error })
    }

})


const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.bcpmthz.mongodb.net/?retryWrites=true&w=majority`).then(() => {
    app.listen(3000)
    console.log('Conectou-se ao banco!')
}).catch((err) => console.log(err))

