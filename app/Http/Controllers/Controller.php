<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;
    public function successResponse($data,$message="Success")
    {
        return response()->json([
            'status'=>'success',
            'data'=>$data,
            'status_code'=>200,
            'message'=>$message
        ]);
    }
}
