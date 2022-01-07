<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
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
}
