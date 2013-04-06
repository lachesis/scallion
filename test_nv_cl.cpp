/* compile with:
 * g++ test_nv_cl.cpp -o test_nv_cl -I/usr/local/cuda-5.0/include/ -L /usr/lib/nvidia-current/ -lOpenCL 
 */

#include <CL/cl.h> 

#include <iostream> 
using namespace std; 

int main() 
{ 
cl_platform_id platform; 
cl_uint num_platforms; 
cl_device_id devices[2]; 
cl_uint num_devices; 
cl_int err; 
char info[256]; 
int i; 

clGetPlatformIDs(1, &platform, &num_platforms); 
cout << "Found " << num_platforms << " platforms." << endl; 

clGetPlatformInfo(platform, CL_PLATFORM_NAME, 256, info, 0); 
cout << "Platform name: " << info << endl; 

clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 2, devices, &num_devices); 
cout << "Found " << num_devices << " devices." << endl; 

for (i = 0; i < num_devices; ++i) 
{ 
clGetDeviceInfo(devices[i], CL_DEVICE_NAME, 256, info, 0); 
cout << "Device " << i << " name: " << info << endl; 
}	

return 0;	
}
