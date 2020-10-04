<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class UserController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['status'=>false, 'message'=>'Akun tidak dikenal'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['status'=>false, 'message'=>'Token tidak bisa dibuat'], 500);
        }
        return response()->json(['status'=>true, 'message'=>'Berhasil masuk', 'token'=>$token]);
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $user = User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);
        $token = JWTAuth::fromUser($user);
        return response()->json(['status'=>true, 'message'=>'Berhasil masuk', 'token'=>$token]);
    }

    public function getAuthenticatedUser()
    {
        try {
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['status'=>false, 'message'=>'Akun tidak ditemukan'], 404);
            }
        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['status'=>false, 'message'=>'Token tidak berlaku lagi'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['status'=>false, 'message'=>'Token tidak valid'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['status'=>false, 'message'=>'Token tidak ditemukan'], $e->getStatusCode());
        }
        return response()->json(['status'=>true, 'message'=>'Selamat datang', 'user'=>$user]);
    }
}
