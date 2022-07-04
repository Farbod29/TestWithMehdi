<?php

namespace App\Http\Controllers\API\Auth;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\PersonalAccessToken;
use Modules\UserVerification\Entities\UserVerification;
class LoginController extends Controller
{

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function login()
    {

        $data=request()->validate([
            'email' => 'required',
            'password' => 'required',
            // 'captcha' => 'required|captcha_api:'. request('key')
        ]);
        $user=User::where("email",$data['email'])->first();
        if(!$user) return response()->json([
            'ok'=>false,
            'message'=>__("Wrong email or password")
        ]);
        if(Hash::check($data['password'],$user->password)){
            $token=$user->createToken('login');
            $payload=$user->toArray();
            $payload['exp']=now()->addSeconds(config("sanctum.expiration"))->getTimestamp();
            return response()->json([
                'ok'=>true,
                'userData'=>$user,
                'idTokenPayload'=>$payload,
                'idToken'=>$token->accessToken->id,
                'accessToken'=>$token->plainTextToken,
                'tokenExpiry'=>now()->addMinutes(config("sanctum.expiration"))
            ]);
        }
        return response()->json(['ok'=>false,'message'=>__("Wrong email or password")]);
    }
    public function logout()
    {
        if(auth()->check() && auth()->user()->tokens){
            auth()->user()->tokens()->delete();
        }
        return response()->json([
            'ok'=>true
        ]);
    }

    public function check()
    {
        $user=auth()->user();
        $token=PersonalAccessToken::findToken(request()->bearerToken());
        if(!$token) abort(401);
        $payload=$user->toArray();
        $payload['exp']=now()->addSeconds(config("sanctum.expiration"))->getTimestamp();
        return response()->json([
            'ok'=>true,
            'userData'=>$user,
            'idTokenPayload'=>$payload,
            'idToken'=>$token->id,
            'accessToken'=>$token->plainTextToken,
            'tokenExpiry'=>now()->addSeconds(config("sanctum.expiration"))
        ]);
    }
}
