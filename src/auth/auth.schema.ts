import {Prop,Schema,SchemaFactory} from '@nestjs/mongoose'
import { Document } from 'mongoose'

@Schema()
export class User extends Document{
    @Prop()
    name : string;

    @Prop()
    email: string;

    @Prop()
    password: string;
}

export const AuthSchema = SchemaFactory.createForClass(User);