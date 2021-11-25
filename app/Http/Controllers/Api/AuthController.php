<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\Client;
use Illuminate\Support\Facades\Http;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email'         =>  ['required', 'string', 'email', 'max:255'],
            'password'      =>  ['required', 'string'],
        ]);

        if ($validator->fails()) {
            return response(['errors'=>$validator->errors()->all()], 422);
        }

        if( auth()->attempt($request->only(['email', 'password'])) ) {
            //$user = auth()->user();
            $oClient = Client::where('password_client', 3)->first();
            $response = Http::asForm()->post(url('oauth/token'), [
                'grant_type' => 'password',
                'client_id' => $oClient->id,
                'client_secret' => $oClient->secret,
                'username' => $request->input('email'),
                'password' => $request->input('password'),
                'scope' => '*',
            ]);

            //  TODO : Gestion des erreurs
            $result = $response->json();

            return response()->json([
                'success'   =>  true,
                'data'      =>  [
                    'user'              =>  auth()->user(),
                    'access_token'      =>  $result['access_token'],
                    'refresh_token'     =>  $result['refresh_token'],
                    'expires_in'        =>  $result['expires_in'],
                    'client_id'         =>  $oClient->id,
                    'client_secret'     =>  $oClient->secret,
                ]
            ]);
        }

        return response()->json([
            'success'   =>  false,
        ]);
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'          =>  ['string', 'max:255'],
            'email'         =>  ['required', 'string', 'email', 'max:255', 'unique:users,email'],
            'password'      =>  ['required', 'string', 'min:6', 'confirmed'],
        ]);

        if ($validator->fails()) {
            return response(['errors'=>$validator->errors()->all()], 422);
        }

        $user = User::create([
            'name'          =>  $request->input('name'),
            'email'         =>  $request->input('email'),
            'password'      =>  Hash::make($request->input('password')),
        ]);

        auth()->loginUsingId($user->id);

        $oClient = Client::where('password_client', 3)->first();
        $response = Http::asForm()->post(url('oauth/token'), [
            'grant_type' => 'password',
            'client_id' => $oClient->id,
            'client_secret' => $oClient->secret,
            'username' => $request->input('email'),
            'password' => $request->input('password'),
            'scope' => '*',
        ]);

        //  TODO : Gestion des erreurs
        $result = $response->json();

        return response()->json([
            'success'   =>  true,
            'data'      =>  [
                'user'          =>  $user,
                'access_token'  =>  $result['access_token'],
                'refresh_token' =>  $result['refresh_token'],
                'expires_in'        =>  $result['expires_in'],
                //'client_id'         =>  $oClient->id,
                //'client_secret'     =>  $oClient->secret,
            ]
        ]);
    }

    public function user()
    {
        $user = null;
        if( auth()->check() ) {
            $user = auth()->user();
        }

        return response()->json([
            'success'   =>  true,
            'data'      =>  [
                'auth'      =>  auth()->check(),
                'user'      =>  auth()->check() ? $user : null,
            ]
        ]);
    }


    public function token(Request $request)
    {
        $oClient = Client::where('password_client', 3)->first();
        $response = Http::asForm()->post(url('oauth/token'), [
            'grant_type' => 'refresh_token',
            'refresh_token' => $request->input('refresh_token'),
            'client_id' => $oClient->id,
            'client_secret' => $oClient->secret,
            'scope' => '',
        ]);

        //  TODO : Gestion des erreurs
        $result = $response->json();
        //dd($result);

        return response()->json([
            'success'   =>  true,
            'data'      =>  [
                'access_token'     =>  $result['access_token'],
                'refresh_token'     =>  $result['refresh_token'],
            ]
        ]);
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json([
            'success'   =>  true,
        ]);
    }
}


