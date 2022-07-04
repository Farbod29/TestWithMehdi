<?php

namespace App\Http\Controllers\API\Auth;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\PersonalAccessToken;
use Modules\UserVerification\Entities\UserVerification;
class RegisterController extends Controller
{

     /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function register()
    {
        $data=request()->validate([
            'email' => 'required|unique:users',
            'name'=>'required',
            'password' => 'required|confirmed',
            'first_name'=>'required',
            'last_name'=>'required'
            // 'captcha' => 'required|captcha_api:'. request('key')
        ]);
        $user=User::create([
            'email'=>$data['email'],
            'password'=>Hash::make($data['password']),
            'name'=>$data['name']
        ]);
        $user->profile()->create([
            'first_name'=>$data['first_name'],
            'last_name'=>$data['last_name']
        ]);
        $token=$user->createToken('login');
        Auth::login($user);
        $payload=$user->toArray();
        $payload['exp']=now()->addSeconds(config("sanctum.expiration"))->getTimestamp();
        return $this->successResponse([
            'user'=>$user->fresh(),
            'access_token'=>$token->plainTextToken,
            'token_expiry'=>now()->addMinutes(config("sanctum.expiration"))
        ]);
    }
    public function register_otp(Request $request)
    {
        $data=$request->validate([
            'otp'=>'required',
            'mobile'=>'required_if:type,mobile',
            'email'=>'required_if:type,email',
            'type'=>'required|in:mobile,email',
            // 'email'=>'nullable',
            'username'=>'nullable|min:5|unique:users',
            'password'=>'nullable',
            'device_id'=>'nullable',
            'firebase_token'=>'nullable',
        ]);

        if($data['type'] == "mobile"){
            $result=UserVerification::validate($request->get("otp"),[
                'mobile'=>$request->get("mobile")
            ],"verification","mobile");
        }else if($data['type'] == "email"){
            $result=UserVerification::validate($request->get("otp"),[
                'email'=>$request->get("email")
            ],"verification","email");
        }
        unset($data['otp']);
        if($result == 1){
            unset($data['type']);
            $user = User::firstOrCreate($data);
            if(isset($data['mobile'])){
                unset($data['mobile']);
            }else if(isset($data['email'])){
                unset($data['email']);
            }

            unset($data['username']);
            unset($data['device_id']);
            unset($data['firebase_token']);
            $user->profile()->firstOrCreate($data);
            auth()->login($user);
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

        }else if($result == 2){
            return response()->json([
                'ok'=>false,
                'message'=>trans("userverification::auth.otp_max_attempts")
            ]);
        }else if($result == 0){
            return response()->json([
                'ok'=>false,
                'message'=>trans("userverification::auth.otp_not_found")
            ]);
        }
    }
}
