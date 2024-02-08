const Usuario = require("../models/Usuario");
const Proyecto = require("../models/Proyecto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config({path: "variables.env"});

// Crea y firma un jwt
const crearToken = (usuario, secreta, expiresIn)=>{
    const { id, email } = usuario

    return jwt.sign({id, email}, secreta, { expiresIn })
}

const resolvers = {
    Query: {
       obtenerProyectos: async (_, {}, ctx)=>{
            const proyectos = await Proyecto.find({ creador: ctx.usuario.id});
            
            return proyectos;
       } 
    },
    Mutation: {
        crearUsuario: async(_, {input})=>{
            const { email, password } = input;

            const existeUsuario = await Usuario.findOne({ email });

            if(existeUsuario){
                throw new Error("El usuario ya está registrado");
            }

            try{
                //Hashear password
                const salt = await bcrypt.genSalt(10);
                input.password = await bcrypt.hash(password, salt);

                //Registrar
                const nuevoUsuario = new Usuario(input);
                nuevoUsuario.save();

                return "Usuario Creado Correctamente";
            }catch(error){
                console.log(error);
            }
        },
        autenticarUsuario: async(_, {input})=>{
            const { email, password } = input;

            //Si el usuario existe
            const existeUsuario = await Usuario.findOne({ email });

            if(!existeUsuario){
                throw new Error("El usuario no existe");
            }

            //Si el password es correcto
            const passwordCorrecto = await bcrypt.compare(password, existeUsuario.password);

            if(!passwordCorrecto){
                throw new Error("Password incorrecto");
            } 

            //Dar acceso a la app
            return {
                token: crearToken(existeUsuario, process.env.SECRETA, "2hr")
            }

        },
        nuevoProyecto: async(_, {input}, ctx)=>{
            
            try{
                const proyecto = new Proyecto(input);

                proyecto.creador = ctx.usuario.id;

                const resultado = await proyecto.save();
                return resultado;
            }catch(error){
                console.log(error);
            }
        },
        actualizarProyecto: async(_, {id, input}, ctx)=>{
            //Revisar si el proyecto existe
            let proyecto = await Proyecto.findById(id);

            if(!proyecto){
                throw new Error("Proyecto no encontrado");
            }
            //Revisar si quien lo edita es el creador
            if(proyecto.creador.toString() !== ctx.usuario.id){
                throw new Error("No tienes las credenciales para editar");
            }
            //Guardar proyecto
            proyecto = await Proyecto.findOneAndUpdate({_id: id}, input, { new: true});
            return proyecto;
        },
        eliminarProyecto: async(_, {id}, ctx)=>{
            //Revisar si el proyecto existe
            let proyecto = await Proyecto.findById(id);

            if(!proyecto){
                throw new Error("Proyecto no encontrado");
            }
            //Revisar si quien lo edita es el creador
            if(proyecto.creador.toString() !== ctx.usuario.id){
                throw new Error("No tienes las credenciales para editar");
            }

            //Eliminar
            await Proyecto.findOneAndDelete({_id: id});

            return "Proyecto Eliminado";
        }
    }
}

module.exports = resolvers;