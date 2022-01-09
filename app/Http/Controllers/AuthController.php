<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Mail\ForgotPassword;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            //Check email vs password valid
            if(Auth::attempt($request->only('email', 'password'))) {
                $user = Auth::user();
                $token = $user->createToken('app')->accessToken;
                return response()->json([
                    'status' => 'success',
                    'token' => $token,
                    'user' => $user
                ]);
            }

            return response()->json([
                'status' => 'fail',
                'message' => 'Invalid email or password'
            ], 401);

        } catch (\Exception $exception) {
            return response()->json([
                'status' => 'fail',
                'message' => $exception->getMessage()
            ], 500);
        }
    }

    public function register(RegisterRequest $request)
    {
        try {
            $validated = $request->validated();

            //create user & token
            $user = User::create([
               'name' => $validated['name'],
               'email' => $validated['email'],
               'password' => Hash::make($validated['password'])
            ]);

            $token = $user->createToken('app')->accessToken;
            return response()->json([
                'status' => 'success',
                'token' => $token,
                'user' => $user
            ]);

        } catch (\Exception $exception) {
            return response()->json([
                'status' => 'fail',
                'message' => $exception->getMessage()
            ], 500);
        }
    }

    public function forgotPassword(Request $request)
    {
        //validate
        $validator = Validator::make($request->all(), [
            'email' => 'required|email'
        ]);
        if($validator->fails()) {
            return response()->json([
                'status' => 'fail',
                'message' => $validator->errors()
            ], 400);
        }
        $email = $request->email;

        //check email exist
        if(User::where('email', $email)->doesntExist()) {
            return response()->json([
                'status' => 'fail',
                'message' => 'Invalid Email'
            ], 401);
        }

        // Generate Random Token
        $token = rand(10, 100000);
        try {
            //insert email & token to password_resets table
            DB::table('password_resets')->insert([
                'email' => $email,
                'token' => $token,
                'created_at' => Carbon::now()
            ]);

            //send mail to user
            Mail::to($email)->send(new ForgotPassword($token));

            return response()->json([
                'status' => 'success',
                'message' => 'Request Password Sent To Your Email'
            ]);
        } catch (\Exception $exception) {
            return response()->json([
                'status' => 'fail',
                'message' => $exception->getMessage()
            ], 500);
        }
    }

    public function resetPassword(Request $request)
    {
        //validate
        $validator = Validator::make($request->all(), [
            'token' => 'required',
            'password' => 'required|min:6|confirmed'
        ]);
        if($validator->fails()) {
            return response()->json([
                'status' => 'fail',
                'message' => $validator->errors()
            ], 400);
        }
        $validated = $validator->validated();

        //check token valid
        if(DB::table('password_resets')->where('token', $validated['token'])->doesntExist()) {
            return response()->json([
                'status' => 'fail',
                'message' => 'Token Invalid'
            ], 400);
        }

        //change password & delete token record
        $email = DB::table('password_resets')->where('token', $validated['token'])->select('email')->first()->email;
        User::where('email', $email)->update([
            'password' => Hash::make($validated['password'])
        ]);

        DB::table('password_resets')->where('token', $validated['token'])->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'Password Changed Successfully'
        ]);
    }

    public function profile()
    {
        return Auth::user();
    }
}
