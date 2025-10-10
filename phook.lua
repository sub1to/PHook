project "PHook"
	uuid				"e95178a0-9e4f-436c-bafc-50d1bf53e870"
	kind				"StaticLib"
	
	buildoptions {
		"/Zc:threadSafeInit-",
	}

	rtti ("Off")

	files
	{
		"PHook/**.cpp",
		"PHook/**.h",
		"PHook/**.asm",
		"PHook/**.inc",
	}
	
	vpaths {
		["*"]			= { "PHook" },
	}
	
	includedirs {
		"PHook/",
	}
	
	libdirs {
		"PHook",
	}
		
	filter "configurations:Debug*"
		defines { "DEBUG" }
		optimize "Off"
		symbols "On"
		
	filter "configurations:Dev*"
		flags { "LinkTimeOptimization" }
		optimize "Full"
		symbols "Off"
		
	filter "configurations:Release*"
		flags { "LinkTimeOptimization" }
		defines { "NDEBUG" }
		optimize "Full"
		symbols "Off"
			