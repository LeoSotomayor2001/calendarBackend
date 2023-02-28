const express= require('express');
const bcrypt=require('bcryptjs');
const Usuario = require('../models/Usuario');
const { generarJWT } = require('../helpers/JWT');


const crearUsuario=async(req,res=express.response)=>{

    const {email,password}=req.body;

    try {
        let usuario= await Usuario.findOne({email: email})

        if(usuario){
            return res.status(400).json({
                ok:false,
                msg:'Un usuario existe con ese correo'
            });
        }

        usuario=new Usuario(req.body);

        //*Encriptar contraseña
        const salt=bcrypt.genSaltSync();
        usuario.password=bcrypt.hashSync(password,salt);

        //*Guardar el usuario
        await usuario.save();

        //*Generar JWT

        const token=await generarJWT(usuario.id,usuario.name);

        res.status(201).json({
            ok:true,
            uid:usuario.id,
            name:usuario.name,
            token
        });
        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok:false,
            msg:'Por favor hable con el administrador'
        })
    }
    
    
}

const loginUsuario=async(req,res=express.response)=>{

    const {email,password}=req.body;

    try {
        const usuario= await Usuario.findOne({email: email})

        if(!usuario){
            return res.status(400).json({
                ok:false,
                msg:'No hay un usuario registrado con ese email'
            });
        }
        //*Confirmar constraseñas

        const validPassword=bcrypt.compareSync(password,usuario.password);

        if(!validPassword){
            return res.status(400).json({
                ok:false,
                msg:'Contraseña no valida'
            })
        }

         //*Generar JWT

         const token=await generarJWT(usuario.id,usuario.name);

        res.json({
            ok:true,
            uid:usuario.id,
            name:usuario.name,
            token
        });

        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok:false,
            msg:'Por favor hable con el administrador'
        })
    }

}

const revalidarToken=async(req,res=express.response)=>{

    const uid=req.uid;
    const name=req.name;

    //*Generar un nuevo JWT y retornarlo
    const token=await generarJWT(uid,name);
    
    res.json({
        ok:true,
        token
    });
}

module.exports={
    crearUsuario,
    loginUsuario,
    revalidarToken
}