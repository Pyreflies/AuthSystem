import {Prop,Schema,SchemaFactory} from '@nestjs/mongoose'
import { Document,Types  } from 'mongoose'

@Schema()
export class User extends Document{
    @Prop({ required: true, unique: true })
    username: string;

    @Prop()
    name: string;

    @Prop({ required: true, unique: true })
    email: string;

    @Prop({ required: true })
    password: string;
}

export const AuthSchema = SchemaFactory.createForClass(User);
